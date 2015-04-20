# coding: utf-8
# test for url.rb
#require 'spec_helper'
require "test_utils"
require "logstash/filters/url"
#require "/Users/morton_swimmer/src/logstash-filter-url/logstash/filters/url"

describe LogStash::Filters::URL do
  extend LogStash::RSpec

   describe "parse url" do
    config <<-CONFIG
      filter {
        url {
          source => "source_url"
          target => "dest_url"
        }
      }
    CONFIG

    event = {
      "source_url" =>  "http://example.com/p/a/t/h" 
    }

    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"example.com", "path"=>"/p/a/t/h", "filename"=>"h", "num_path"=>4, "port"=>80 }
    end
  end

end
