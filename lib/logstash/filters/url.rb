# url.rb
require "logstash/filters/base"
require "logstash/namespace"
require 'uri'
require 'cgi'

class LogStash::Filters::URL < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your logstash config.
  #
  # filter {
  #   url {
  #     source => "source_url_field_name"
  #     target => "target_field_name"
  #   }
  # }
  config_name "url"

  milestone 1

  # which field to source the URL from
  config :source, :validate => :string, :required => true
  # which field to put the resulting structure to
  config :target, :validate => :string, :required => true
  
  public
  def register
    # nothing to do
  end # def register

  public
  def filter(event)
    # return nothing unless there's an actual filter event
    return unless filter?(event)

    event[@target] = parse(event[@source])
 
    # filter_matched should go in the last line of our successful code 
    filter_matched(event)
  end # def filter

  private
  def parse(url)
    fail_it = false
    url_thing = url.to_s
    url_parts = {}
    begin
      fail_it = url != url_thing
      #puts "trying #{url_thing}"
      u = URI url_thing
      url_parts['scheme'] = u.scheme
      url_parts['port'] = u.port if u.port
      url_parts['username'] = u.user if u.user
      url_parts['password'] = u.password if u.password
      url_parts['hostname'] = u.hostname if u.hostname
      url_parts['path'] = CGI.unescape(u.path) if u.path
      if url_parts['path']
        path_split = url_parts['path'].split(/\//).select { |p| p.length > 0 }
        url_parts['filename'] = path_split[-1] if path_split[-1]
        url_parts['num_path'] = path_split.length
      end
      url_parts['querystring'] = CGI.unescape(u.query) if u.query
      if url_parts['querystring'] && url_parts['querystring'].length > 1
        tmp_hash = {}
        url_parts['querystring'].split(/[;&]/).map{ |qkv| 
          kv = qkv.split(/=/)
          if kv[1]
            tmp_hash[kv[0]] = (tmp_hash[kv[0]] || []) << kv[1]
          else
            tmp_hash[kv[0]] = (tmp_hash[kv[0]] || [])
          end
        }
        url_parts['query'] = tmp_hash.map { |k, vs| { parameter: k, values: vs } }  unless tmp_hash.empty?
        url_parts['num_query'] = url_parts['querystring'].split(/[;&]/).select { |p| p.length > 0 }.length
      end
      url_parts['fragment'] = u.fragment if u.fragment
      
      if url_parts['hostname'] && (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ =~ url_parts['hostname'])
        url_parts['host'] = { 'addr' => {'ip' => url_parts['hostname'], 'ipv4' => url_parts['hostname'], 'port' => url_parts['port'] } }
        url_parts.delete 'hostname'
      end
      # Regex from http://stackoverflow.com/a/17871737
      if url_parts['hostname'] && (/^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/ =~ url_parts['hostname'])
        url_parts['host'] = { 'addr' => {'ip' => url_parts['hostname'], 'ipv6' => url_parts['hostname'], 'port' => url_parts['port'] } }
        url_parts.delete 'hostname'
      end
    rescue URI::InvalidURIError => e
      $stderr.puts "The URL '#{url_thing}' failed to be parsed. Trying to sanitize it and attempting another parse."
      url_thing = url.gsub(/[^\w\d:;&#\/\.=]/, '+')
      #
      retry unless fail_it
      #puts "failing"
    end
    url_parts
  end
  
end # class LogStash::Filters::URL
