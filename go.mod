module github.com/flynn/go-tuf

go 1.12

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Sirupsen/logrus v1.3.0 // indirect
	github.com/boltdb/bolt v1.3.1 // indirect
	github.com/coreos/bbolt v1.3.2
	github.com/docker/docker v1.13.1
	github.com/dustin/go-humanize v1.0.0
	github.com/flynn/go-docopt v0.0.0-20140912013429-f6dd2ebbb31e
	github.com/kr/pretty v0.1.0 // indirect
	github.com/tent/canonical-json-go v0.0.0-20130607151641-96e4ba3a7613
	golang.org/x/crypto v0.0.0-20190211182817-74369b46fc67
	golang.org/x/sys v0.0.0-20190215142949-d0b11bdaac8a // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127
)

//replace github.com/tent/canonical-json-go => ./vendor/github.com/tent/canonical-json-go

replace github.com/Sirupsen/logrus v1.3.0 => github.com/sirupsen/logrus v1.3.0
