# InfraTrack
> Identify adversary command and control (C&C) infrastructure via pre-written Shodan and Censys rules. Other options for this project include finding newly registered domains that match a set 
of specific wordlists, that can be easily modified. Lastly, the user can get a report from GreyNoise, VirusTotal and RiskIQ (for IP addresses), and VirusTotal, RiskIQ and WhoIs (for domains).


<!-- ![](screenshot.png) -->
<!---
## Installation

OS X & Linux:

```sh
npm install my-crazy-module --save
```

Windows:

```sh
edit autoexec.bat
```
--->
## Usage example

```python
python3 infratrack.py --hunt '/path/to/shodan/censys/sig/files'

python3 infratrack.py --domain 'example.com'

python3 infratrack.py --ip '1.2.3.4'
```

Output for domains
![Screenshot](https://github.com/mrippey/InfraTrack/blob/master/images/Domain_Summ.png)

Output for an IP adress
![Screenshot](https://github.com/mrippey/InfraTrack/blob/master/images/IP_Summ.png)

<!---
A few motivating and useful examples of how your product can be used. Spice this up with code blocks and potentially more screenshots.

_For more examples and usage, please refer to the [Wiki][wiki]._

## Development setup

Describe how to install all development dependencies and how to run an automated test-suite of some kind. Potentially do this for multiple platforms.

```sh
make install
npm test
```
--->
## Release History
<!---
* 0.2.1
    * CHANGE: Update docs (module code remains unchanged)
* 0.2.0
    * CHANGE: Remove `setDefaultXYZ()`
    * ADD: Add `init()` -->
* 1.0.0
    * CHANGE: Details coming soon.
* 0.1.1 (27 May 2022)
    * CHANGE: Separate InfraTrack into multiple modules
* 0.1.0
    * The first proper release
    * CHANGE: Cleanup code, combine Domain & IP Summary, add "Machine Learning" algorithm to identify malicious URL's. 
    * CHANGE(2): Write Shodan and Censys query output to CSV file to ease upload into Splunk, ELK, or other analysis platform.
    * TODO: Implement correlation analysis among already gathered data.
* 0.0.1
    * Work in progress

## About

 [@nahamike01](https://twitter.com/nahamike01) 

Distributed under the GNU GPL v3.0 license. See ``LICENSE`` for more information.

<!-- [https://github.com/yourname/github-link](https://github.com/mrippey/) -->
<!---
## Contributing

1. Fork it (<https://github.com/yourname/yourproject/fork>)
2. Create your feature branch (`git checkout -b feature/fooBar`)
3. Commit your changes (`git commit -am 'Add some fooBar'`)
4. Push to the branch (`git push origin feature/fooBar`)
5. Create a new Pull Request
--->
<!-- Markdown link & img dfn's 
[npm-image]: https://img.shields.io/npm/v/datadog-metrics.svg?style=flat-square
[npm-url]: https://npmjs.org/package/datadog-metrics
[npm-downloads]: https://img.shields.io/npm/dm/datadog-metrics.svg?style=flat-square
[travis-image]: https://img.shields.io/travis/dbader/node-datadog-metrics/master.svg?style=flat-square
[travis-url]: https://travis-ci.org/dbader/node-datadog-metrics
[wiki]: https://github.com/yourname/yourproject/wiki
--->

