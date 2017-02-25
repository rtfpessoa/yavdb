# Yet Another Vulnerability Database

[![Codacy Badge](https://api.codacy.com/project/badge/Grade/00298529610b41f4a6ec380550ea45de)](https://www.codacy.com/app/rtfpessoa/yavdb?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=rtfpessoa/yavdb&amp;utm_campaign=Badge_Grade)
[![Codacy Badge](https://api.codacy.com/project/badge/Coverage/00298529610b41f4a6ec380550ea45de)](https://www.codacy.com/app/rtfpessoa/yavdb?utm_source=github.com&utm_medium=referral&utm_content=rtfpessoa/yavdb&utm_campaign=Badge_Coverage)
[![CircleCI](https://circleci.com/gh/rtfpessoa/yavdb.svg?style=svg)](https://circleci.com/gh/rtfpessoa/yavdb)

The Free and Open Source vulnerability database.

This database aims to aggregate multiple sources of vulnerabilities for the most common package managers helping 
developers identify and fix know vulnerabilities in their apps.

The sources for this database include 
[Rubysec](https://rubysec.com/),
[snyk](https://snyk.io/),
[OSSIndex](https://ossindex.net/),
[NodeSecurity](https://nodesecurity.io/),
[Friends of PHP](https://github.com/FriendsOfPHP/security-advisories),
[Magento Related Security Advisories](https://github.com/victims/victims-cve-db),
[Victims CVE Database](https://github.com/victims/victims-cve-db)

## Prerequisites

* Ruby 2.3 or newer

## Installation

```sh
bundle exec rake install
```

```sh
gem install yavdb --pre
```

> Notice the `--pre` in the end

## TODO:

#### Tests
    
* Sources
    - [ ] [Rubysec](lib/yavdb/sources/ruby_advisory.rb)
    - [X] [snyk](lib/yavdb/sources/snyk_io.rb)
    - [ ] [OSSIndex](lib/yavdb/sources/ossindex.rb)
    - [X] [NodeSecurity](lib/yavdb/sources/nodesecurity_io.rb)
    - [ ] [Friends of PHP and Magento Related Security Advisories](lib/yavdb/sources/friends_of_php.rb)
    - [ ] [Victims CVE Database](lib/yavdb/sources/victims.rb)
* Others
    - [ ] [Advisory](lib/yavdb/dtos/advisory.rb)

#### Features/Improvements

- [ ] Merge  duplicates
- [ ] Scrape [NVD](https://nvd.nist.gov/) for other package manager vulnerabilities
- [ ] Find more sources

### Help

    Commands:
      yavdb download                                                            # Download a previously generated database from the official yavdb repository into yavdb-path.
        Options: p, [--yavdb-path=YAVDB-PATH]  # Default: <HOME>/.yavdb/yavdb
      yavdb generate                                                            # Crawl several sources and generate a local database in database-path.
        Options: p, [--database-path=DATABASE-PATH]  # Default: <PWD>/database
      yavdb help [COMMAND]                                                      # Describe available commands or one specific command
      yavdb list --package-manager=PACKAGE-MANAGER --package-name=PACKAGE-NAME  # List vulnerabilities from database-path of package-name for package-manager.   
        Options: p, [--database-path=DATABASE-PATH]  # Default: <HOME>/.yavdb/yavdb/database
    
    Options:
      [--verbose], [--no-verbose]

## Development

After checking out the repo, run `bin/setup` to install dependencies.
Then, run `bundle exec rake spec` to run the tests.
You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.
To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`,
which will create a git tag for the version,
push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rtfpessoa/yavdb.
This project is intended to be a safe, welcoming space for collaboration,
and contributors are expected to adhere to the [Contributor Covenant](http://contributor-covenant.org) code of conduct.

## Copyright

Copyright (c) 2017-present Rodrigo Fernandes.
See [LICENSE](https://github.com/rtfpessoa/yavdb/blob/master/LICENSE) for details.
