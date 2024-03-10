#pragma once

namespace RaceMenuVRHooks
{

	namespace LeakFix
	{
		static inline std::uintptr_t target = 0x17CB98;
		class NIOVTaskDeferredMask : public SKSE::detail::TaskDelegate
		{
			typedef std::shared_ptr<void*> ItemAttributeDataPtr;

		public:
			void Run() override{};
			void Dispose() override{};
			void DisposeMethod()
			{
				delete this;
			};

			byte padding[0x10];
			RE::NiPointer<RE::NiAVObject> m_object;  // 0x20;
			ItemAttributeDataPtr m_overrides;        // 0x28;
		};
		static_assert(sizeof(NIOVTaskDeferredMask) == 0x30);
		static_assert(offsetof(NIOVTaskDeferredMask, m_object) == 0x18);
		static_assert(offsetof(NIOVTaskDeferredMask, m_overrides) == 0x20);

		static void DisposeStatic(NIOVTaskDeferredMask* a_self)
		{
			a_self->DisposeMethod();
		};

		static void Install(std::uintptr_t a_base)
		{
			std::uintptr_t targetAddr = a_base + target;
			std::uintptr_t newTargetAddr = (std::uintptr_t)(DisposeStatic);

			REL::safe_write(targetAddr, (void*)&newTargetAddr, sizeof(newTargetAddr));
		}
	}

#define dataHandler RE::TESDataHandler::GetSingleton()

	struct TrampolineJmp : Xbyak::CodeGenerator
	{
		TrampolineJmp(std::uintptr_t func)
		{
			Xbyak::Label funcLabel;

			jmp(ptr[rip + funcLabel]);
			L(funcLabel);
			dq(func);
		}
	};

	struct ASMJmp : Xbyak::CodeGenerator
	{
		ASMJmp(std::uintptr_t func, std::uintptr_t jmpAddr)
		{
			Xbyak::Label funcLabel;

			sub(rsp, 0x20);
			call(ptr[rip + funcLabel]);
			add(rsp, 0x20);
			mov(rcx, jmpAddr);
			jmp(rcx);

			L(funcLabel);
			dq(func);
		}
	};

	const RE::TESFile* LookupFileByFormID(RE::FormID a_formID)
	{
		auto index = a_formID >> 24;
		if (index == 0xFE) {
			auto smallIndex = a_formID >> 12 & 0xFFF;
			return const_cast<RE::TESFile*>(dataHandler->LookupLoadedLightModByIndex(smallIndex));
		}
		return const_cast<RE::TESFile*>(dataHandler->LookupLoadedModByIndex(index));
	}

	RE::FormID GetFormIDFromFile(const RE::TESFile* a_file, std::uint32_t a_rawFormID)
	{
		RE::FormID result = a_rawFormID & 0xFFFFFF;  // Strip ESP index
		if (a_file->IsLight()) {
			result &= 0xFFF;  // Strip ESL index if light
		}

		result |= (a_file->compileIndex << 24);  // Add ESP index
		if (a_file->IsLight()) {
			result |= (a_file->smallFileCompileIndex << 12);  // Add ESL index if light
		}

		return result;
	}

	RE::TESForm* GetFormFromFile(const RE::TESFile* a_file, std::uint32_t a_rawFormID)
	{
		return RE::TESForm::LookupByID(GetFormIDFromFile(a_file, a_rawFormID));
	}

	namespace FileLookupHooks
	{
		std::string GetFormIdentifier(void* a_unk, RE::TESForm* form)
		{
			char formName[MAX_PATH];
			std::uint8_t modIndex = form->formID >> 24;
			std::uint32_t modForm = form->formID & 0xFFFFFF;

			RE::TESFile* modInfo = nullptr;
			if (modIndex == 0xFE) {
				std::uint16_t lightIndex = (form->formID >> 12) & 0xFFF;
				modInfo = const_cast<RE::TESFile*>(dataHandler->LookupLoadedLightModByIndex(lightIndex));
			} else {
				modInfo = const_cast<RE::TESFile*>(dataHandler->LookupLoadedModByIndex(modIndex));
			}

			if (modInfo) {
				sprintf_s(formName, "%s|%06X", modInfo->fileName, modForm);
			}

			return formName;
		}

		RE::TESForm* GetFormFromIdentifier(const std::string& formIdentifier)
		{
			std::size_t pos = formIdentifier.find_first_of('|');
			std::string modName = formIdentifier.substr(0, pos);
			std::string modForm = formIdentifier.substr(pos + 1);

			std::uint32_t formId = 0;
			sscanf_s(modForm.c_str(), "%X", &formId);

			const RE::TESFile* modInfo = dataHandler->LookupModByName(modName.c_str());
			if (!modInfo || modInfo->compileIndex == 0xFF) {
				return nullptr;
			}

			return RE::TESForm::LookupByID(GetFormIDFromFile(modInfo, formId));
		}

		void GetModName(void* a_unk, RE::GFxFunctionHandler::Params* args)
		{
			assert(args->argCount >= 1);
			assert(args->args[0].GetType() == RE::GFxValue::ValueType::kNumber);

			std::uint32_t formId = (std::uint32_t)args->args[0].GetNumber();

			const RE::TESFile* modInfo = LookupFileByFormID(formId);
			if (modInfo) {
				args->movie->CreateString(args->retVal, modInfo->fileName);
			}
		}

		struct DeleteFaceGenDataHook
		{
			static inline std::uintptr_t target = 0x94130;

			static const RE::TESFile* GetFileFromForm(std::uint64_t a_unk, RE::TESForm* a_form)
			{
				return LookupFileByFormID(a_form->formID);
			}
			static void Install(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x4B;
				auto end = a_base + target + 0x61;
				REL::safe_fill(start, REL::NOP, end - start);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, end);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(start, result);
			}
		};

		struct LoadExternalCharacterExHook
		{
			static inline std::uintptr_t target = 0x946A0;

			static const RE::TESFile* GetFileFromForm(RE::TESForm* a_form)
			{
				return LookupFileByFormID(a_form->formID);
			}
			static void Install(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x1C3;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x1E0;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x4C, 0x89, 0xF1 };  // mov rcx, r14
				REL::safe_write(start, movRcx, 0x3);
				byte movRdi[] = { 0x48, 0x89, 0xF8 };  // mov rax, rdi
				REL::safe_write(asmEnd, movRdi, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}
		};

		struct SaveBinaryPresetHook
		{
			static inline std::uintptr_t target = 0x62040;

			static const RE::TESFile* GetFileFromForm(RE::TESForm* a_form)
			{
				return LookupFileByFormID(a_form->formID);
			}
			static void Install(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x224;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x23B;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x4C, 0x89, 0xF1 };  // mov rcx, r14
				REL::safe_write(start, movRcx, 0x3);
				byte movRdi[] = { 0x48, 0x89, 0xC6 };  // mov rsi, rax
				REL::safe_write(asmEnd, movRdi, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}
		};

		struct SaveJsonPresetHook
		{
			static inline std::uintptr_t target = 0x5E7C0;

			static const RE::TESFile* GetFileFromForm(RE::TESForm* a_form)
			{
				return LookupFileByFormID(a_form->formID);
			}

			static void InstallSpot1(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x6FA;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x711;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x4C, 0x89, 0xF9 };  // mov rcx, r15
				REL::safe_write(start, movRcx, 0x3);
				byte movRax[] = { 0x49, 0x89, 0xC5 };  // mov r13, rax
				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}

			static void InstallSpot2(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x93E;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x954;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x48, 0x89, 0xC1 };  // mov rcx, rax
				REL::safe_write(start, movRcx, 0x3);
				byte movRax[] = { 0x49, 0x89, 0xC0 };  // mov r8, rax
				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}

			static void InstallSpot3(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x11EA;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x120D;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x48, 0x89, 0xC1 };  // mov rcx, rax
				REL::safe_write(start, movRcx, 0x3);
				byte movRax[] = { 0x49, 0x89, 0xC0 };  // mov r8, rax
				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}

			static void InstallSpot4(std::uintptr_t a_base)
			{
				auto start = a_base + target + 0x337C;
				auto asmStart = start + 0x3;
				auto end = a_base + target + 0x3392;
				auto asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);
				byte movRcx[] = { 0x48, 0x89, 0xD9 };  // mov rcx, rbx
				REL::safe_write(start, movRcx, 0x3);
				byte movRax[] = { 0x49, 0x89, 0xC0 };  // mov r8, rax
				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFileFromForm, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}

			static void Install(std::uintptr_t a_base)
			{
				InstallSpot1(a_base);
				InstallSpot2(a_base);
				InstallSpot3(a_base);
				InstallSpot4(a_base);
			}
		};

		static void Install(std::uintptr_t a_base)
		{
			DeleteFaceGenDataHook::Install(a_base);
			LoadExternalCharacterExHook::Install(a_base);
			SaveBinaryPresetHook::Install(a_base);
			SaveJsonPresetHook::Install(a_base);
		}
	}

	namespace FormIDHooks
	{
		struct Impl_ReadBodyMorphsHook
		{
			static inline std::uintptr_t target = 0xB300;

			static void Install(std::uintptr_t a_base)
			{
				// r13 has file
				// eax has formID
				// ebx needs corrected formID
				std::uintptr_t start = a_base + target + 0x1226;
				std::uintptr_t asmStart = start + 0x6;
				std::uintptr_t end = a_base + target + 0x123A;
				std::uintptr_t asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);

				byte movRcxRdx[] = { 0x4C, 0x89, 0xE9, 0x48, 0x89, 0xC2 };  // mov rcx, r13, mov rdx, rax

				REL::safe_write(start, movRcxRdx, 0x6);

				byte movRax[] = { 0x48, 0x89, 0xC3 };  // mov rbx, rax

				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFormIDFromFile, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				logger::info("size is {}", jmp.getSize());
				auto result = trampoline.allocate(jmp);
				logger::info("Impl_ReadBodyMorphsHook hookin {:x} to jmp to {:x} with base {:x}", asmStart, (std::uintptr_t)result, a_base);

				trampoline.write_branch<5>(asmStart, result);
			}
		};

		struct LoadJsonPresetHook
		{
			static inline std::uintptr_t target = 0x633C0;

			static void Install(std::uintptr_t a_base)
			{
				// rax has file
				// r12d has formID
				// edi needs corrected formID
				std::uintptr_t start = a_base + target + 0xE24;
				std::uintptr_t asmStart = start + 0x6;
				std::uintptr_t end = a_base + target + 0xE33;
				std::uintptr_t asmEnd = end - 0x3;
				REL::safe_fill(start, REL::NOP, end - start);

				byte movRcxRdx[] = { 0x48, 0x89, 0xC1, 0x4C, 0x89, 0xE2 };  // mov rcx, rax, mov rdx, r12

				REL::safe_write(start, movRcxRdx, 0x6);

				byte movRax[] = { 0x48, 0x89, 0xC7 };  // mov rbi, rax

				REL::safe_write(asmEnd, movRax, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFormIDFromFile, asmEnd);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}
		};

		struct LoadBinaryPresetHook
		{
			static inline std::uintptr_t target = 0x66610;

			static void Install(std::uintptr_t a_base)
			{
				// rax has file
				// r12d has formID
				// edi needs corrected formID
				std::uintptr_t start = a_base + target + 0x5C4;
				std::uintptr_t asmStart = start + 0x7;
				std::uintptr_t end = a_base + target + 0x5D9;
				REL::safe_fill(start, REL::NOP, end - start);

				byte movRdx[] = { 0x8b, 0x54, 0x24, 0x4c };  // mov    edx,DWORD PTR [rsp+0x4c]
				REL::safe_write(start, movRdx, 0x4);
				byte movRcx[] = { 0x48, 0x89, 0xC1 };  // mov rcx, rax

				REL::safe_write(start + 0x4, movRcx, 0x3);

				auto jmp = ASMJmp((uintptr_t)GetFormFromFile, end);
				jmp.ready();
				auto& trampoline = SKSE::GetTrampoline();
				auto result = trampoline.allocate(jmp);
				trampoline.write_branch<5>(asmStart, result);
			}
		};

		static void Install(std::uintptr_t a_base)
		{
			logger::info("Installing formID hooks 1");
			Impl_ReadBodyMorphsHook::Install(a_base);
			logger::info("Installing formID hooks 2");
			LoadJsonPresetHook::Install(a_base);
			logger::info("Installing formID hooks 3");
			LoadBinaryPresetHook::Install(a_base);
			logger::info("Installing formID hooks 4");
		}
	}

	struct Patches
	{
		std::string name;
		std::uintptr_t offset;
		void* function;
	};

	std::vector<Patches> patches{
		{ "GetFormIdentifier", 0x32750, FileLookupHooks::GetFormIdentifier },
		{ "GetFormFromIdentifier", 0x32810, FileLookupHooks::GetFormFromIdentifier },
		{ "GetModName", 0xC2A70, FileLookupHooks::GetModName },
	};

	void Install()
	{
		auto racemenu_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("skeevr"));

		constexpr std::size_t gigabyte = static_cast<std::size_t>(1) << 30;
		//constexpr std::size_t module = racemenu_base ;

		// Allocate space near the module's address for all of our assembly hooks to go into
		// Each hook has to be within 2 GB of the trampoline space for the REL 32-bit jmps to work
		// The trampoline logic checks for first available region to allocate from 2 GB below addr to 2 GB above addr
		// So we add a gigabyte to ensure the entire DLL is within 2 GB of the allocated region
		auto& trampoline = SKSE::GetTrampoline();
		trampoline.create(0x200, (void*)(racemenu_base + gigabyte));

		logger::info("Installing patches");
		for (const auto& patch : patches) {
			logger::info("Trying to patch {} at {:x} with {:x}"sv, patch.name, racemenu_base + patch.offset, (std::uintptr_t)patch.function);
			std::uintptr_t target = (uintptr_t)(racemenu_base + patch.offset);
			auto jmp = TrampolineJmp((std::uintptr_t)patch.function);
			REL::safe_write(target, jmp.getCode(), jmp.getSize());

			logger::info("RaceMenu {} patched"sv, patch.name);
		}

		logger::info("Installing file lookup hooks");
		FileLookupHooks::Install(racemenu_base);

		logger::info("Installing leak fix");
		LeakFix::Install(racemenu_base);

		logger::info("Installing formID hooks");
		FormIDHooks::Install(racemenu_base);
	}
}
