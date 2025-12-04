# KH1FM_Re_Toolkit

**A modern toolkit for patching Kingdom Hearts 1 ISO's**

KH1FM_Re_Toolkit is a collection of Python scripts designed to modify a Kingdom Hearts 1: Final Mix PlayStation 2 ISO. This toolkit provides a streamlined and reproducible way to apply custom patches, replace files, and modify the game's data through structured configuration files.

## ✨ Features
- Patch an existing KH1 Final Mix ISO using easy-to-read JSON configs
- Insert, replace, or modify game files contained within the ISO
- Apply custom patch definitions stored separately for modularity
- Includes an optional patch that enables cutscene skipping

## 🚀 Usage
By default, the toolkit expects the original ISO to be named **KHFM.iso** and located in the same directory as the scripts.

The main entry point for this toolkit is:

```bash
python KH1FM_Re_Toolkit.py config.json
```

### Configuration Files
Example configuration files can be found in the `configs/` directory. These illustrate the modes the toolkit can be run in.

### Patch Definitions
An example patch JSON file is available in the `patches/` directory. These files describe specific modifications or injections the toolkit can apply.

Note that while the patch format has an option for compressing files, the scripts do not yet support compressing files.

## 📦 Included Patch: Custom Cutscene Skipping ELF
Alongside this toolkit, a custom patch is provided that injects an additional ELF file into the game's ISO. This ELF enables **cutscene skipping**, providing a faster gameplay experience.

This ELF is a lightly modified version of the original work created by **SH2_LUCK**. Full credit for the base implementation goes to them, and the modifications included here simply adapt their work to integrate properly within the KH1 Final Mix ISO structure.


## 📝 License
This project is released under the **MIT License**. See the LICENSE file for full details.

## 🙏 Acknowledgments
- **SH2_LUCK** for the original ELF implementation enabling early cutscene skipping.
- The KH modding community for their continuous documentation, discoveries, and support.

---
If you encounter issues or have ideas for improvements, feel free to open an issue or submit a pull request!

