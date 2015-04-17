# url.rb
require "logstash/filters/base"
require "logstash/namespace"

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
    scheme_split = url.split(/:/)
    url_parts = {}
    url_parts['scheme'] = scheme_split[0]
    authority = (url[/[\/]{2}([^\/]+)/] || '').gsub(/\/{1,2}/, '')
    puts authority
    url_parts['port'] = authority[-6..-1][/:\d+/][1..-1].to_i if authority.length > 7 && authority[-6..-1][/:\d+/]
    userpass = authority[/[^@]+@/] if authority
    if userpass
      url_parts['username'] = userpass[/[^:@]+/]
      url_parts['password'] = userpass[/:.*/][1..-2] if userpass[/:.*/]
    end
    if authority[-1] == ']'
      url_parts['hostname'] = authority[((authority.rindex('@') || -1) +1)..((authority.rindex(']:') || 0) -1)] if authority
    else
      url_parts['hostname'] = authority[((authority.rindex('@') || -1) +1)..((authority.rindex(':') || 0) -1)] if authority
    end
    md = /\/\/[^\/]+\//.match(url)
    if md
      path_start = md.end(0) -1
      pathpart = url[path_start..-1]
      url_parts['path'] = pathpart[/[^\?]+/]
      url_parts['filename'] = url_parts['path'].split(/\//)[-1] if url_parts['path'].split(/\//)[-1]
      url_parts['num_path'] = url_parts['path'].split(/\//).select {|p| p.length > 0 }.length
      url_parts['querystring'] = pathpart[/\?[^#]+/] if pathpart[/\?[^#]+/]
      if url_parts['querystring']
        url_parts['query'] = url_parts['querystring'][1..-1].split(/[;&]/).map{ |qkv| 
          kv = qkv.split(/=/)
          { parameter: kv[0], value: kv[1] } 
        }
        url_parts['num_query'] = url_parts['querystring'].split(/[;&]/).select { |p| p.length > 0 }.length
      end
      url_parts['fragment'] = pathpart[/#.+/] if pathpart[/#.+/]
    end
    url_parts['port'] = 80 unless url_parts['port'] || url_parts['scheme'] != 'http'
    url_parts['port'] = 443 unless url_parts['port'] || url_parts['scheme'] != 'https'
    # Look for an IPv4 address in the hostname
    if /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ =~ url_parts['hostname']
      url_parts['host'] = { 'addr' => {'ip' => url_parts['hostname'], 'ipv4' => url_parts['hostname'], 'port' => url_parts['port'] } }
      url_parts.delete 'hostname'
    end
    # Regex from http://stackoverflow.com/a/17871737
    if /\[(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\]/ =~ url_parts['hostname']
      url_parts['host'] = { 'addr' => {'ip' => url_parts['hostname'], 'ipv6' => url_parts['hostname'], 'port' => url_parts['port'] } }
      url_parts.delete 'hostname'
    end
    url_parts
  end
  
end # class LogStash::Filters::URL
