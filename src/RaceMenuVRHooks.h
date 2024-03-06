#pragma once

namespace PapyrusUtilVRHooks
{

	static std::unordered_map<std::uint32_t, std::uint32_t> s_savedModIndexMap;

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

	struct UnkFileNameHook {
		
		struct ASMJmp : Xbyak::CodeGenerator
		{
			ASMJmp(std::uintptr_t func, std::uintptr_t jmpAddr)
			{
				Xbyak::Label funcLabel;

				mov(rcx, rdi);
				sub(rsp, 0x20);
				call(ptr[rip + funcLabel]);
				add(rsp, 0x20);
				mov(rdx, rax);
				mov(rcx, jmpAddr);
				jmp(rcx);

				L(funcLabel);
				dq(func);
			}
		};

		static char* GetFileName(RE::TESForm* a_form) {
			logger::info("GetFileName called");
			logger::info("FileName result: {}", a_form->GetFile()->fileName);

			return a_form->GetFile()->fileName;
		}

		static void Install(std::uintptr_t a_base) {
			std::uintptr_t target{ a_base + 0x3C330 + 0xAB };
			std::uintptr_t jmpBack{ a_base + 0x3C330 + 0xC4 };

			auto newCompareCheck = ASMJmp((uintptr_t) GetFileName, jmpBack);
			newCompareCheck.ready();
			int fillRange = jmpBack - target;
			REL::safe_fill(target, REL::NOP, fillRange);
			auto& trampoline = SKSE::GetTrampoline();
			trampoline.create(newCompareCheck.getSize(), (void*)target);
			auto result = trampoline.allocate(newCompareCheck);
			trampoline.write_branch<5>(target, result);
		}
	};

	struct UnkCompileIndex
	{
		struct ASMJmp : Xbyak::CodeGenerator
		{
			ASMJmp(std::uintptr_t func, std::uintptr_t jmpAddr)
			{
				Xbyak::Label funcLabel;

				mov(r8, r15d);
				call(ptr[rip + funcLabel]);
				mov(r15d, rax);
				or_(r15d, r15d);
				mov(rcx, jmpAddr);
				jmp(rcx);

				L(funcLabel);
				dq(func);
			}
		};

		static RE::FormID GetFormIDFromFileName(RE::TESDataHandler* a_handler, char* a_fileName, std::uint32_t a_rawForm)
		{
			auto file = RE::TESDataHandler::GetSingleton()->LookupModByName(a_fileName);
			auto form = a_rawForm;
			if (!file) {
				return a_rawForm | 0xFF;
			}

			form &= 0xFFFFFFu;  // Strip file index, now 0x00XXXXXX;
			if (file->IsLight()) {
				form &= 0xFFFu;  // Strip ESL index, now 0x00000XXX;
				form |= 0xFE000000u;
				form |= file->smallFileCompileIndex << 12;
			} else {
				form |= file->compileIndex << 24;
			}
			
			return form;
		}

		static void Install(std::uintptr_t a_base)
		{
			std::uintptr_t target{ a_base + 0x3C520 + 0x37E };
			std::uintptr_t jmpBack{ a_base + 0x3C520 + 0x38C };

			auto newCompareCheck = ASMJmp((uintptr_t)GetFormIDFromFileName, jmpBack);
			newCompareCheck.ready();
			int fillRange = jmpBack - target;
			REL::safe_fill(target, REL::NOP, fillRange);
			auto& trampoline = SKSE::GetTrampoline();
			trampoline.create(newCompareCheck.getSize(), (void*)target);
			auto result = trampoline.allocate(newCompareCheck);
			trampoline.write_branch<5>(target, result);
		}
	};

	RE::FormID RemapFormFromSave(RE::FormID a_oldForm)
	{
		auto index = a_oldForm >> 24;
		if (index == 0xFF) {
			return a_oldForm;
		}
		auto lightModIndex = (a_oldForm >> 12) & 0xFFF;

		std::uint32_t oldIndex = index == 0xFE ? (0xFE000 | lightModIndex) : index;

		auto it = s_savedModIndexMap.find(oldIndex);
		if (it == s_savedModIndexMap.end()) {
			return 0;
		}

		auto newIndex = it->second;
		if (newIndex > 0xFF) {  // FEXXX greater than FF, must be ESL
			auto formID = a_oldForm &= 0xFFF;
			return (newIndex << 12 | formID);
		} else {
			auto formID = a_oldForm &= 0xFFFFFF;
			return (newIndex << 24 | formID);
		}
	}


	namespace saveIndexHooks
	{
		struct RemapJmp : Xbyak::CodeGenerator
		{
			RemapJmp(std::uintptr_t jmpAddr, std::uintptr_t func = (uintptr_t) RemapFormFromSave)
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

		struct RemapJmp2 : Xbyak::CodeGenerator
		{
			RemapJmp2(std::uintptr_t jmpAddr, std::uintptr_t func = (uintptr_t)RemapFormFromSave)
			{
				Xbyak::Label funcLabel;

				sub(rsp, 0x20);
				call(ptr[rip + funcLabel]);
				add(rsp, 0x20);
				mov(rcx, rax);
				mov(rdx, jmpAddr);
				jmp(rdx);

				L(funcLabel);
				dq(func);
			}
		};

		struct Unk1
		{
			static void Install(std::uintptr_t a_base)
			{
				std::uintptr_t baseFunc = a_base + 0x17F90;
				std::uintptr_t target{ baseFunc + 0x3F1 };
				std::uintptr_t jmpBack{ baseFunc + 0x431 };


				auto jmpCode = RemapJmp(jmpBack);
				jmpCode.ready();
				int fillRange = jmpBack - target;
				REL::safe_fill(target, REL::NOP, fillRange);
				REL::safe_write(target, jmpCode.getCode(), jmpCode.getSize());

				if (jmpCode.getSize() > fillRange) {
					auto message = std::format("Unk1 trampoline code is {:x} bytes too big", jmpCode.getSize() - fillRange);
					pstl::report_and_fail(message);
				}
			}
		};

		struct Unk2
		{
			static void Install(std::uintptr_t a_base)
			{
				std::uintptr_t baseFunc = a_base + 0xC9D0;
				std::uintptr_t target{ baseFunc + 0x2CA };
				std::uintptr_t jmpBack{ baseFunc + 0x310 };

				auto jmpCode = RemapJmp(jmpBack);
				jmpCode.ready();
				int fillRange = jmpBack - target;
				REL::safe_fill(target, REL::NOP, fillRange);
				REL::safe_write(target, jmpCode.getCode(), jmpCode.getSize());

				if (jmpCode.getSize() > fillRange) {
					auto message = std::format("Unk2 trampoline code is {:x} bytes too big", jmpCode.getSize() - fillRange);
					pstl::report_and_fail(message);
				}
			}
		};

		struct Unk3
		{
			static void Install(std::uintptr_t a_base)
			{
				std::uintptr_t baseFunc = a_base + 0x6B010;
				std::uintptr_t target{ baseFunc + 0xEE };
				std::uintptr_t jmpBack{ baseFunc + 0x12D };

				auto jmpCode = RemapJmp2(jmpBack);
				jmpCode.ready();
				int fillRange = jmpBack - target;
				REL::safe_fill(target, REL::NOP, fillRange);
				REL::safe_write(target, jmpCode.getCode(), jmpCode.getSize());

				if (jmpCode.getSize() > fillRange) {
					auto message = std::format("Unk3 trampoline code is {:x} bytes too big", jmpCode.getSize() - fillRange);
					pstl::report_and_fail(message);
				}
			}
		};

		struct Unk4
		{
			static void Install(std::uintptr_t a_base)
			{
				std::uintptr_t baseFunc = a_base + 0x6B010; // Same func as Unk3
				std::uintptr_t target{ baseFunc + 0x20B };
				std::uintptr_t jmpBack{ baseFunc + 0x24B };

				auto jmpCode = RemapJmp2(jmpBack);
				jmpCode.ready();
				int fillRange = jmpBack - target;
				REL::safe_fill(target, REL::NOP, fillRange);
				REL::safe_write(target, jmpCode.getCode(), jmpCode.getSize());

				if (jmpCode.getSize() > fillRange) {
					auto message = std::format("Unk4 trampoline code is {:x} bytes too big", jmpCode.getSize() - fillRange);
					pstl::report_and_fail(message);
				}
			}
		};

		static void Install(std::uintptr_t a_base)
		{
			Unk1::Install(a_base);
			Unk2::Install(a_base);
			Unk3::Install(a_base);
			Unk4::Install(a_base);
		}
	};

	void SaveMods(SKSE::SerializationInterface* intfc)
	{
		auto handler = RE::TESDataHandler::GetSingleton();

		std::uint16_t regCount = 0;
		std::uint16_t lightCount = 0;
		std::uint16_t fileCount = 0;
		for (auto file : handler->files) {
			if (file && file->compileIndex != 0xFF) {
				if (file->compileIndex != 0xFE) {
					regCount++;
				} else {
					lightCount++;
				}
			}
		}
		fileCount = regCount + lightCount;
		bool saveSuccessful = true;
		saveSuccessful &= intfc->OpenRecord('MODS', 0);
		saveSuccessful &= intfc->WriteRecordData(&fileCount, sizeof(fileCount));

		logger::info("Saving plugin list ({} regular {} light {} total):", regCount, lightCount, fileCount);

		for (auto file : handler->files) {
			if (file && file->compileIndex != 0xFF) {
				saveSuccessful &= intfc->WriteRecordData(&file->compileIndex, sizeof(file->compileIndex));
				if (file->compileIndex == 0xFE) {
					saveSuccessful &= intfc->WriteRecordData(&file->smallFileCompileIndex, sizeof(file->smallFileCompileIndex));
				}

				std::uint16_t nameLen = strlen(file->fileName);
				saveSuccessful &= intfc->WriteRecordData(&nameLen, sizeof(nameLen));
				saveSuccessful &= intfc->WriteRecordData(file->fileName, nameLen);
				if (file->compileIndex != 0xFE) {
					logger::info("\t[{}]\t{}", file->compileIndex, file->fileName);
				} else {
					logger::info("\t[FE:{}]\t{}", file->smallFileCompileIndex, file->fileName);
				}
			}
		}
		if (!saveSuccessful) {
			logger::error("SKSE cosave failed");
		}
	}

	void LoadMods(SKSE::SerializationInterface* intfc) {

		s_savedModIndexMap.clear();

		auto handler = RE::TESDataHandler::GetSingleton();

		logger::info("Loading plugin list:");

		char name[0x104] = { 0 };
		std::uint16_t nameLen = 0;

		std::uint16_t modCount = 0;
		intfc->ReadRecordData(&modCount, sizeof(modCount));
		for (std::uint32_t i = 0; i < modCount; i++) {
			std::uint8_t modIndex = 0xFF;
			std::uint16_t lightModIndex = 0xFFFF;
			intfc->ReadRecordData(&modIndex, sizeof(modIndex));
			if (modIndex == 0xFE) {
				intfc->ReadRecordData(&lightModIndex, sizeof(lightModIndex));
			}

			intfc->ReadRecordData(&nameLen, sizeof(nameLen));
			intfc->ReadRecordData(&name, nameLen);
			name[nameLen] = 0;

			std::uint32_t newIndex = 0xFF;
			std::uint32_t oldIndex = modIndex == 0xFE ? (0xFE000 | lightModIndex) : modIndex;

			const RE::TESFile* modInfo = handler->LookupModByName(name);
			if (modInfo) {
				newIndex = modInfo->GetPartialIndex();
			}

			s_savedModIndexMap[oldIndex] = newIndex;

			logger::info("\t({} -> {})\t{}", oldIndex, newIndex, name);
		}
	}

	void LoadLegacyMods(std::uint64_t a_unk) {
		// Do nothing (Maybe we should to be safe?
	}

	RE::TESForm* LoadSavedMatchingForm(std::uint64_t a_unk)
	{
		// Best guess, this function loads a data type that has both formType and formID encoded in the 64 bits
		// Only loads form if the formID remaps to a TESForm with the encoded formType
		if (!a_unk) {
			return 0;
		}
		std::uint32_t formType = a_unk >> 32;
		RE::FormID oldFormID = a_unk & 0xFFFFFFFF;

		RE::FormID newFormID = RemapFormFromSave(oldFormID);
		if (!newFormID) {
			return 0;
		}

		auto form = RE::TESForm::LookupByID(newFormID);

		if (!form || form->formType.underlying() != formType) {
			return 0;
		}

		return form;
	}
	
	struct Patches
	{
		std::string name;
		std::uintptr_t offset;
		void* function;
	};

	std::vector<Patches> patches{
		{ "SaveMods", 0x3BCB0, SaveMods },
		{ "LoadMods", 0x3BB40, LoadMods },
		{ "LoadLegacyMods", 0x3BDA0, LoadLegacyMods },
		{ "LoadFormWithTypeUNK", 0x3BFF0, LoadSavedMatchingForm }
	};

	void Install()
	{
		auto papyrusutil_base = reinterpret_cast<uintptr_t>(GetModuleHandleA("PapyrusUtil"));

		for (const auto& patch : patches) {
			logger::info("Trying to patch {} at {:x} with {:x}"sv, patch.name, papyrusutil_base + patch.offset, (std::uintptr_t)patch.function);
			std::uintptr_t target = (uintptr_t)(papyrusutil_base + patch.offset);
			auto jmp = TrampolineJmp((std::uintptr_t)patch.function);
			REL::safe_write(target, jmp.getCode(), jmp.getSize());

			logger::info("PapyrusUtil {} patched"sv, patch.name);
		}

		UnkFileNameHook::Install(papyrusutil_base);
		UnkCompileIndex::Install(papyrusutil_base);
		saveIndexHooks::Install(papyrusutil_base);
	}
}
