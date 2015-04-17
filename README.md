# logstash-filter-url
Break a URL down into it's components and insert into a Logstash event

# Can be used like this
logstash -f example.conf --pluginpath .

# Where the configuration file could contain this:

	filter {
		url {
			source => "source_url_field_name"
			target => "target_field_name"
		}
	}

