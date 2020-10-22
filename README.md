<!-- PROJECT LOGO -->
```
                         _______________________________     _________         .    .
                        /                               \   (..       \_    ,  |\  /|
                        |  Fish are friends, not food.   \   \       O  \  /|  \ \/ /
                        \_______________________________  \   \______    \/ |   \  /
                                                        \__\     vvvv\    \ |   /  |
                                                                 \^^^^  ==   \_/   |
                                                                  `\_   ===    \.  |
                                                                  / /\_   \ /      |
                                                                 |/   \_  \|      /
                                                                        \________/
```
<p align="center">
  <h1 align="center">bruce</h1>
  <p align="center">
    Accelerating the parsing PCAPS into JSON format as well as ability to extract files from those PCAPS
    <br><br>
    <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/ezaspy/markdown-snippets/issues">
    <img src="https://img.shields.io/github/issues/markdown-templates/markdown-snippets.svg" alt="Issues">
    </a>
    <br><br>
    <a href="https://github.com/ezaspy/bruce">View Demo</a>
    ·
    <a href="https://github.com/ezaspy/bruce/issues">Report Bug</a>
    ·
    <a href="https://github.com/ezaspy/bruce/issues">Request Feature</a>
    <br><br>
  </p>
</p>

<!-- TABLE OF CONTENTS -->
## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
* [Usage](#usage)
* [Roadmap](#roadmap)
* [Contributing](#contributing)
* [License](#license)
* [Contact](#contact)
* [Acknowledgements](#acknowledgements)


<br><br>
<!-- ABOUT THE PROJECT -->
## About The Project

bruce has been created to help fellow digitial forensicators with reading and interpreting PCAP files without the need to trawl though Wireshark. bruce utilises tshark to convert the PCAPS and outputs them into JSON to then be indexed into log management or SIEM platforms alongside other data sources.
<br>

### Built With

* [Python 3.7+](https://www.python.org)
* [Visual Studio Code](https://code.visualstudio.com)
<br><br>


<!-- Prerequisites -->
## Prerequisites

* [tshark](https://tshark.dev)
<br><br>


<!-- USAGE EXAMPLES -->
## Usage
`python3 bruce.py [-h] [-e] <directory_of_PCAPS>`
### Example
`python3 bruce.py -e /pcaps/`
### Support
See the [support](https://github.com/ezaspy/bruce/issues) for a list of commands and additional third-party tools to help with preparing images or data for bruce.
<br><br>


<!-- ROADMAP -->
## Roadmap

* String searching

See the [open issues](https://github.com/ezaspy/bruce/issues) for a list of proposed features (and known issues).
<br>

See the [changes](https://github.com/ezaspy/bruce/issues) for a list of previous changes to bruce.
<br><br>


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
<br><br>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.
<br><br>


<!-- CONTACT -->
## Contact

ezaspy - ezaspython@gmail.com

Project Link: [https://github.com/ezaspy/bruce](https://github.com/ezaspy/bruce)
<br><br>


<!-- ACKNOWLEDGEMENTS -->
## Acknowledgements
* [Wireshark (tshark)](https://tshark.dev)
* [Best-README-Template](https://github.com/othneildrew/Best-README-Template)
* [Img Shields](https://shields.io)
* [Choose an Open Source License](https://choosealicense.com)
* [GitHub Pages](https://pages.github.com)



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/ezaspy/bruce.svg?style=flat-square
[contributors-url]: https://github.com/ezaspy/bruce/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ezaspy/bruce.svg?style=flat-square
[forks-url]: https://github.com/ezaspy/bruce/network/members
[stars-shield]: https://img.shields.io/github/stars/ezaspy/bruce.svg?style=flat-square
[stars-url]: https://github.com/ezaspy/bruce/stargazers
[issues-shield]: https://img.shields.io/github/issues/ezaspy/bruce.svg?style=flat-square
[issues-url]: https://github.com/ezaspy/bruce/issues
[license-shield]: https://img.shields.io/github/license/ezaspy/bruce.svg?style=flat-square
[license-url]: https://github.com/ezaspy/bruce/master/LICENSE.txt
[product-screenshot]: images/screenshot.png
