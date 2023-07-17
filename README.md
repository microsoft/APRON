# APRON: Authenticated and Progressive System Image Renovation

This repository contains an early-stage prototype for APRON,
which was presented at [USENIX Annual Technical Conference (USENIX ATC) 2023](https://www.usenix.org/conference/atc23/)

APRON is a novel mechanism to minimize the system downtime due to recovery
by securely fixing requested invalid blocks through using on-demand renovation
and a Merkle hash tree.

Please refer to [our paper](https://www.microsoft.com/en-us/research/publication/apron-authenticated-and-progressive-system-image-renovation/) for all technical details.

## Repository organization

1. [module](./module) contains the APRON kernel module.
1. [metagen](./metagen) contains metadata generation tools for deduplication.
1. [initramfs-tools](./initramfs-tools) contains scripts to create or be included in initramfs.
1. [extra](./extra) contains simple tools for evaluation (i.e., corrupt system image files, check zero blocks).

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

## Trademarks

This project may contain trademarks or logos for projects, products, or services. Authorized use of Microsoft 
trademarks or logos is subject to and must follow 
[Microsoft's Trademark & Brand Guidelines](https://www.microsoft.com/en-us/legal/intellectualproperty/trademarks/usage/general).
Use of Microsoft trademarks or logos in modified versions of this project must not cause confusion or imply Microsoft sponsorship.
Any use of third-party trademarks or logos are subject to those third-party's policies.
