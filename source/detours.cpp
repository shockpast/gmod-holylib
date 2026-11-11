#include "detours.h"
#include <convar.h>
#include "tier0/dbg.h"
#include <cstring>

#if defined(SYSTEM_LINUX) && ARCHITECTURE_IS_X86
#include <elf.h>
#include <link.h>
#endif

// memdbgon must be the last include file in a .cpp file!!!
#include "tier0/memdbgon.h"

#ifndef PROJECT_NAME // When people copy this file they might not have it defined, so we just fallback.
#define PROJECT_NAME "project"
#endif

SymbolFinder Detour::symfinder;
#if defined(SYSTEM_LINUX) && ARCHITECTURE_IS_X86
static void* FindLinux32Signature(void* pModule, const Symbol& symbol)
{
	if (!pModule || !symbol.length)
		return nullptr;

	const auto* map = static_cast<const link_map*>(pModule);
	const uintptr_t base = map->l_addr;
	const auto* header = reinterpret_cast<const Elf32_Ehdr*>(base);
	if (std::memcmp(header->e_ident, ELFMAG, SELFMAG) != 0 ||
		header->e_ident[EI_CLASS] != ELFCLASS32 || header->e_ident[EI_DATA] != ELFDATA2LSB ||
		header->e_machine != EM_386 || header->e_type != ET_DYN)
		return nullptr;

	const auto* segments = reinterpret_cast<const Elf32_Phdr*>(base + header->e_phoff);
	const auto* pattern = reinterpret_cast<const uint8_t*>(symbol.name.data());
	// The dependency scanner assumes executable code starts at RVA zero.
	// Current SRCDS libraries instead have a separate executable PT_LOAD.
	for (uint16_t segment = 0; segment < header->e_phnum; ++segment)
	{
		const auto& phdr = segments[segment];
		if (phdr.p_type != PT_LOAD || (phdr.p_flags & (PF_R | PF_X)) != (PF_R | PF_X) ||
			phdr.p_filesz < symbol.length)
			continue;

		auto* begin = reinterpret_cast<uint8_t*>(base + phdr.p_vaddr);
		const size_t last = phdr.p_filesz - symbol.length;
		for (size_t position = 0; position <= last; ++position)
		{
			size_t byte = 0;
			while (byte < symbol.length && (pattern[byte] == '*' || pattern[byte] == begin[position + byte]))
				++byte;

			if (byte == symbol.length)
				return begin + position;
		}
	}

	return nullptr;
}
#endif

void* Detour::GetFunction(void* pModule, const Symbol& pSymbol)
{
#if defined(SYSTEM_LINUX) && ARCHITECTURE_IS_X86
	if (pSymbol.type == Symbol::Type::Signature)
	{
		void* address = FindLinux32Signature(pModule, pSymbol);
		if (address && pSymbol.offset)
		{
			const auto* match = static_cast<const uint8_t*>(address);
			// The PC thunk returns to ADD reg, imm32, where this signature starts.
			// offset selects a direct GOTOFF disp32, never a GOT pointer slot.
			int32_t gotDisplacement;
			int32_t globalDisplacement;
			std::memcpy(&gotDisplacement, match + 2, sizeof(gotDisplacement));
			std::memcpy(&globalDisplacement, match + pSymbol.offset, sizeof(globalDisplacement));
			// Return the address of the global's storage, preserving caller dereferences.
			return reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(match) + gotDisplacement + globalDisplacement);
		}

		return address;
	}
#endif

	return symfinder.Resolve(pModule, pSymbol.name.c_str(), pSymbol.length);
}


struct DetourEntry
{
	DetourEntry() : detourName(""), nCategory(0), pHookFunc(nullptr), pTargetFunc(nullptr) {}

	DetourEntry(std::string name, unsigned int category, void* hookFunc, void* targetFunc)
	{
		detourName = name;
		nCategory = category;
		pHookFunc = hookFunc;
		pTargetFunc = targetFunc;
	}

	std::string detourName;
	unsigned int nCategory;
	void* pHookFunc;
	void* pTargetFunc;
};

static unordered_set<std::string> pDisabledDetours;
static unordered_set<std::string> pFailedDetours;
static unordered_map<std::string, unsigned int> pLoadedDetours;
static unordered_map<Detouring::Hook*, DetourEntry> pDetourInfo;
static unordered_map<unsigned int, unordered_set<Detouring::Hook*>> g_pDetours = {};
void Detour::Create(Detouring::Hook* pHook, const char* strName, void* pModule, Symbol pSymbol, void* pHookFunc, unsigned int category, bool bEnable)
{
	if (pDisabledDetours.find(strName) != pDisabledDetours.end())
	{
		Msg(PROJECT_NAME ": Detour %s was disabled!\n", strName);
		return;
	}

	if (pLoadedDetours.find(strName) != pLoadedDetours.end())
	{
		Warning(PROJECT_NAME ": Detour %s was already loaded! Are you using the same name twice?\n", strName);
		// Do not return since that could still break it. Though still warn others!
	}

	void* func = Detour::GetFunction(pModule, pSymbol);
	if (!CheckFunction(func, strName))
		return;

	pHook->Create(func, pHookFunc);

	if (pDetourInfo.find(pHook) == pDetourInfo.end())
		pDetourInfo[pHook] = {strName, category, pHookFunc, func};

	if (!DETOUR_ISVALID((*pHook)))
	{
		Warning(PROJECT_NAME ": Failed to detour %s!\n", strName);
		if (pFailedDetours.find(strName) == pFailedDetours.end())
			pFailedDetours.insert(strName);
	} else { // Loaded successfully
		if (g_pDetours[category].find(pHook) == g_pDetours[category].end())
			g_pDetours[category].insert(pHook);
	}

	if (bEnable)
		Detour::EnableHook(pHook);
	else
		pHook->Destroy(); // We create dit just to verify.
}

void Detour::EnableHook(Detouring::Hook* pHook)
{
	auto it = pDetourInfo.find(pHook);
	if (it == pDetourInfo.end())
	{
		Warning(PROJECT_NAME " - Detour::EnableHook: Tried to use a hook that didn't go through Detour::Create!\n");
		return;
	}

	pHook->Create(it->second.pTargetFunc, it->second.pHookFunc);
	pHook->Enable();

	if (pLoadedDetours.find(it->second.detourName) == pLoadedDetours.end())
		pLoadedDetours[it->second.detourName] = it->second.nCategory;
	else
		Warning(PROJECT_NAME " - Detour::EnableHook: Tried to use Detour::EnableHook on a hook that is already enabled! (%s)\n", it->second.detourName.c_str());
}

void Detour::DisableHook(Detouring::Hook* pHook)
{
	auto it = pDetourInfo.find(pHook);
	if (it == pDetourInfo.end())
	{
		Warning(PROJECT_NAME " - Detour::DisableHook: Tried to use a hook that didn't go through Detour::Create!\n");
		return;
	}

	pHook->Disable();
	pHook->Destroy();

	auto loadedIT = pLoadedDetours.find(it->second.detourName);
	if (loadedIT != pLoadedDetours.end())
		pLoadedDetours.erase(loadedIT);
	else
		Warning("Tried to use Detour::DisableHook on a hook that is already enabled! (%s)\n", it->second.detourName.c_str());
}

void Detour::Remove(unsigned int category) // NOTE: Do we need to check if the provided category is valid?
{
	for (Detouring::Hook* hook : g_pDetours[category]) {
		if (hook->IsEnabled())
		{
			hook->Disable();
			hook->Destroy();
		}

		auto it = pDetourInfo.find(hook);
		if (it != pDetourInfo.end())
			pDetourInfo.erase(it);
	}
	g_pDetours[category].clear();

	// Remove them from our loaded list.
	for (auto it = pLoadedDetours.begin(); it != pLoadedDetours.end(); )
	{
		if (it->second == category)
			it = pLoadedDetours.erase(it);
		else
			it++;
	}
}

void Detour::ReportLeak()
{
	for (auto& [id, hooks]: g_pDetours)
		if (hooks.size() > 0)
			Msg(PROJECT_NAME ": ID %d failed to shutdown it's detours!\n", id);
}

const unordered_set<std::string>& Detour::GetDisabledDetours()
{
	return pDisabledDetours;
}

const unordered_set<std::string>& Detour::GetFailedDetours()
{
	return pFailedDetours;
}

const unordered_map<std::string, unsigned int>& Detour::GetLoadedDetours()
{
	return pLoadedDetours;
}

static void ToggleDetour(const CCommand& args)
{
	if (args.ArgC() < 1 || V_stricmp(args.Arg(1), "") == 0)
	{
		Msg("Disabled Detours:\n");
		for (auto it = pDisabledDetours.begin(); it != pDisabledDetours.end(); ++it)
			Msg("	- \"%s\"\n", it->c_str());

		return;
	}
	
	auto it = pDisabledDetours.find(args.Arg(1));
	if (it != pDisabledDetours.end())
	{
		pDisabledDetours.erase(it);
		Msg("Enabled detour %s!\n", args.Arg(1));
		return;
	}

	pDisabledDetours.insert(args.Arg(1));
	Msg("Disabled detour %s!\n", args.Arg(1));
}
static ConCommand toggledetour("holylib_toggledetour", ToggleDetour, "Debug command. Enables/Disables the given detour.", 0);