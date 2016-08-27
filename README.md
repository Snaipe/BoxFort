# BoxFort

[![Unix Build Status](https://api.travis-ci.org/Snaipe/BoxFort.svg?branch=master)](https://travis-ci.org/Snaipe/BoxFort) 
[![Windows Build Status](https://ci.appveyor.com/api/projects/status/github/Snaipe/BoxFort?svg=true&branch=master)](https://ci.appveyor.com/project/Snaipe/BoxFort/branch/master)
[![License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](https://github.com/Snaipe/BoxFort/blob/master/LICENSE) 
[![Version](https://img.shields.io/badge/version-experimental-orange.svg?style=flat)](https://github.com/Snaipe/BoxFort/releases) 

A simple, cross-platform sandboxing C library powering [Criterion][criterion].

**Warning**: This library is experimental. APIs may change without notice until Beta is hit. Use at your own risk.

BoxFort provides a simple API to run user code in isolated processes.

Although BoxFort provides some kind of security of the parent process
from spawned sandboxes, a sandbox has by default the same system
permissions and access than its parent, and is hence, without care,
ill-fitted for security purposes.

The main goal of this project **is not** security, but portable code
isolation -- if you want complete system isolation, consider using
properly configured containers.

[criterion]: https://github.com/Snaipe/Criterion
