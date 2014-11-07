vutr
====


Lightweight CVE tracker.


### Installation


Use [pip](http://www.pip-installer.org/en/latest/index.html) to install vutr:

```bash
$ pip install vutr
```


### Commands


#### vutr add <keyword> <pattern>

Add new keyword and regular expression pattern

`keyword`: label for a tracked item

`pattern`: regular expression (PCRE), matched against the CVE descriptions


Example: `vutr add Python "(([cjp]ython)|pypy)"`


#### vutr update

Fetch the newest CVE feed

Typically used from cron

Example hourly crontab: `37 * * * * vutr update >> /tmp/vutr.log`


#### vutr list [from date]

List found CVEs

`from date` (optional) syntax: `YYYY-MM-DD` or `YYYY-MM` or `YYYY`


### License

```
vutr is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

vutr is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with vutr. If not, see < http://www.gnu.org/licenses/ >.

(C) 2014- by Adam Tauber, <asciimoo@gmail.com>
```
