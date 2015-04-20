# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.authors       = ["Morton Swimmer"]
  s.email         = ["morton_swimmer@trendmicro.de"]
  s.description   = %q{parse a url into it's components}
  s.summary       = %q{A logstash plugin to parse a url in an event into it's components and store the nested resulting object into the event}
  s.homepage      = ""
  s.license       = "Apache License (2.0)"

  # Files
  s.files         = `git ls-files`.split("\n")
                                         
  # Tests
  s.test_files    = s.files.grep(%r{^(test|spec|features)/})
  
  s.name          = "logstash-filter-url"
  s.require_paths = ["lib"]
  s.version       = "0.2"

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core", '>= 1.4.0', '< 2.0.0'
  s.add_development_dependency 'logstash-devutils'
  
end
