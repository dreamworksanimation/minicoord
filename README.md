# minicoord - part of the [MoonRay](https://github.com/OpenMoonRay/openmoonray) project
Policies concerning [Governance](https://github.com/OpenMoonRay/openmoonray/blob/main/GOVERNANCE.md), [Code of Conduct](https://github.com/OpenMoonRay/openmoonray/blob/main/CODE_OF_CONDUCT.md), and [Contribution](https://github.com/OpenMoonRay/openmoonray/blob/main/CONTRIBUTING.md) are available in the overarching MoonRay project, defined in the [`OpenMoonRay/openmoonray` GitHub repository superproject](https://github.com/OpenMoonRay/openmoonray).

minicoord is a Python service that manages a pool of render machines.  This code is a simplified Python
implementation of the full (Java) Arras Coordinator service used at DWA.  It is less robust than the
full version, and lacks some of the more advanced machine allocation features, but should be sufficient
to demonstrate Arras multi-machine execution of Moonray.

