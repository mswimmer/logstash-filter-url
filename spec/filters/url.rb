# coding: utf-8
# test for url.rb
require "test_utils"
require "logstash/filters/url"

STDCONF = <<-CONFIG
      filter {
        url {
          source => "source_url"
          target => "dest_url"
        }
      }
    CONFIG

describe LogStash::Filters::URL do
  extend LogStash::RSpec

  describe "parse url http://example.com/p/a/t/h" do
    config STDCONF
    
    event = { "source_url" =>  "http://example.com/p/a/t/h"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"example.com", "path"=>"/p/a/t/h", "filename"=>"h", "num_path"=>4, "port"=>80 }
    end
  end

  describe "parse url foo:xyz" do
    config STDCONF
    
    event = { "source_url" =>  "foo:xyz"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"foo"}
    end
  end

#  describe "parse url some.host.com:80/index.html" do
#    config STDCONF
#    
#    event = { "source_url" =>  "some.host.com:80/index.html"  }
#    sample event do
#      insist { subject["dest_url"] } == {"hostname" => "some.host.com", "port" => 80, "path" => "/index.html", "filename" => "index.html"}
#    end
#  end

  describe "parse url https://user@example.com/x/y/z" do
    config STDCONF
    
    event = { "source_url" => "https://user@example.com/x/y/z" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"https", "username"=>"user", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "port"=>443}
    end
  end

  describe "parse url http://user:password@example.com/x/y/z" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com/x/y/z" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3}
    end
  end

  describe "parse url http://user:password@example.com:8888/x/y/z" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com:8888/x/y/z" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3}
    end
  end

  describe "parse url http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "querystring"=>"a=1&b=2&c=&d=4", "query"=>[{:parameter=>"a", :values=>["1"]}, {:parameter=>"b", :values=>["2"]}, {:parameter=>"c", :values=>[]}, {:parameter=>"d", :values=>["4"]}], "num_query"=>4}
    end
  end

  describe "parse url http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4&d=5&d=6" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4&d=5&d=6" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "querystring"=>"a=1&b=2&c=&d=4&d=5&d=6", "query"=>[{:parameter=>"a", :values=>["1"]}, {:parameter=>"b", :values=>["2"]}, {:parameter=>"c", :values=>[]}, {:parameter=>"d", :values=>["4", "5", "6"]}], "num_query"=>6}
    end
  end

  describe "parse url http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4;p1" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4;p1" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "querystring"=>"a=1&b=2&c=&d=4;p1", "query"=>[{:parameter=>"a", :values=>["1"]}, {:parameter=>"b", :values=>["2"]}, {:parameter=>"c", :values=>[]}, {:parameter=>"d", :values=>["4"]}, {:parameter=>"p1", :values=>[]}], "num_query"=>5}
    end
  end

  describe "parse url http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4;p1#f1" do
    config STDCONF
    
    event = { "source_url" => "http://user:password@example.com:8888/x/y/z?a=1&b=2&c=&d=4;p1#f1" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "hostname"=>"example.com", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "querystring"=>"a=1&b=2&c=&d=4;p1", "query"=>[{:parameter=>"a", :values=>["1"]}, {:parameter=>"b", :values=>["2"]}, {:parameter=>"c", :values=>[]}, {:parameter=>"d", :values=>["4"]}, {:parameter=>"p1", :values=>[]}], "num_query"=>5, "fragment"=>"f1"}
    end
  end

  describe "parse url http://192.168.1.2/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://192.168.1.2/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"192.168.1.2", "ipv4"=>"192.168.1.2", "port"=>80}}}
    end
  end

  describe "parse url http://user@192.168.1.2/x/y/z" do
    config STDCONF
    
    event = { "source_url" => "http://user@192.168.1.2/x/y/z" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "username"=>"user", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"192.168.1.2", "ipv4"=>"192.168.1.2", "port"=>80}}}
    end
  end

  describe "parse url http://user:password@192.168.1.2/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://user:password@192.168.1.2/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "username"=>"user", "password"=>"password", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"192.168.1.2", "ipv4"=>"192.168.1.2", "port"=>80}}}
    end
  end

  describe "parse url http://user:password@192.168.1.2:8888/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://user:password@192.168.1.2:8888/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"192.168.1.2", "ipv4"=>"192.168.1.2", "port"=>8888}}}
    end
  end

  describe "parse url http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "ipv6"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "port"=>80}}}
    end
  end

  describe "parse url http://[3ffe:2a00:100:7031::1]/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://[3ffe:2a00:100:7031::1]/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"3ffe:2a00:100:7031::1", "ipv6"=>"3ffe:2a00:100:7031::1", "port"=>80}}}
    end
  end

  describe "parse url http://[::192.9.5.5]/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://[::192.9.5.5]/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"::192.9.5.5", "ipv6"=>"::192.9.5.5", "port"=>80}}}
    end
  end

  describe "parse url http://user@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://user@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "username"=>"user", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "ipv6"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "port"=>80}}}
    end
  end

  describe "parse url http://user:password@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://user:password@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "username"=>"user", "password"=>"password", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "ipv6"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "port"=>80}}}
    end
  end


  describe "parse url http://user:password@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:8888/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "http://user:password@[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:8888/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>8888, "username"=>"user", "password"=>"password", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3, "host"=>{"addr"=>{"ip"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "ipv6"=>"FEDC:BA98:7654:3210:FEDC:BA98:7654:3210", "port"=>8888}}}
    end
  end


  describe "parse url http://ex/x/q/r" do
    config STDCONF
    
    event = { "source_url" =>  "http://ex/x/q/r"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"ex", "path"=>"/x/q/r", "filename"=>"r", "num_path"=>3, "port"=>80}
    end
  end


  describe "parse url http://ex/x/q/r#s" do
    config STDCONF
    
    event = { "source_url" =>  "http://ex/x/q/r#s"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"ex", "path"=>"/x/q/r", "filename"=>"r", "num_path"=>3, "fragment"=>"s"}
    end
  end


  describe "parse url http://ex/x/q/r#s/t" do
    config STDCONF
    
    event = { "source_url" =>  "http://ex/x/q/r#s/t"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"ex", "path"=>"/x/q/r", "filename"=>"r", "num_path"=>3, "fragment"=>"s/t"}
    end
  end

  describe "parse url ftp://ex/x/q/r" do
    config STDCONF
    
    event = { "source_url" =>  "ftp://ex/x/q/r"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"ftp", "port"=>21, "hostname"=>"ex", "path"=>"x/q/r", "filename"=>"r", "num_path"=>3}
    end
  end

  describe "parse url file:/example2/x/y/z" do
    config STDCONF
    
    event = { "source_url" =>  "file:/example2/x/y/z"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"file", "path" => "/example2/x/y/z", "filename"=>"z", "num_path"=>4 }
    end
  end

  describe "parse url file:/ex/x/q/r#s" do
    config STDCONF
    
    event = { "source_url" =>  "file:/ex/x/q/r#s"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"file", "path"=>"/ex/x/q/r", "filename"=>"r", "num_path"=>4, "fragment"=>"s"}
    end
  end

  describe "parse url file://meetings.example.com/cal#m1" do
    config STDCONF
    
    event = { "source_url" =>  "file://meetings.example.com/cal#m1"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"file", "hostname"=>"meetings.example.com", "path"=>"/cal", "filename"=>"cal", "num_path"=>1, "fragment"=>"m1"}
    end
  end

  describe "parse url file:/some/dir/#blort" do
    config STDCONF
    
    event = { "source_url" =>  "file:/some/dir/#blort"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"file", "path"=>"/some/dir/", "filename"=>"dir", "num_path"=>2, "fragment"=>"blort"}
    end
  end

  describe "parse url http://example/x/y%2Fz" do
    config STDCONF
    
    event = { "source_url" =>  "http://example/x/y%2Fz"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"example", "path"=>"/x/y/z", "filename"=>"z", "num_path"=>3}
    end
  end

  describe "parse url http://example/x%2Fabc" do
    config STDCONF
    
    event = { "source_url" =>  "http://example/x%2Fabc"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"example", "path"=>"/x/abc", "filename"=>"abc", "num_path"=>2, "port"=>80}
    end
  end

  describe "parse url http://www.w3.org/2002/01/tr-automation/../../2002/01/tr-automation/tr.rdf" do
    config STDCONF
    
    event = { "source_url" =>  "http://www.w3.org/2002/01/tr-automation/../../2002/01/tr-automation/tr.rdf"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"www.w3.org", "path"=>"/2002/01/tr-automation/../../2002/01/tr-automation/tr.rdf", "filename"=>"tr.rdf", "num_path"=>9, "port"=>80}
    end
  end

  describe "parse url http://example.com/.meta.n3" do
    config STDCONF
    
    event = { "source_url" =>  "http://example.com/.meta.n3"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"example.com", "path"=>"/.meta.n3", "filename"=>".meta.n3", "num_path"=>1, "port"=>80}
    end
  end

  describe "parse url http://xn--0trv4xfvn8el34t.w3.mag.keio.ac.jp/" do
    config STDCONF
    
    event = { "source_url" =>  "http://xn--0trv4xfvn8el34t.w3.mag.keio.ac.jp/"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"xn--0trv4xfvn8el34t.w3.mag.keio.ac.jp", "path"=>"/", "num_path"=>0, "port"=>80}
    end
  end

  describe "parse url http://www.w3.org/International/articles/idn-and-iri/JP%E7%B4%8D%E8%B1%86/%E5%BC%95%E3%81%8D%E5%89%B2%E3%82%8A%E7%B4%8D%E8%B1%86.html" do
    config STDCONF
    
    event = { "source_url" =>  "http://www.w3.org/International/articles/idn-and-iri/JP%E7%B4%8D%E8%B1%86/%E5%BC%95%E3%81%8D%E5%89%B2%E3%82%8A%E7%B4%8D%E8%B1%86.html"  }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "hostname"=>"www.w3.org", "path"=>"/International/articles/idn-and-iri/JP納豆/引き割り納豆.html", "filename"=>"引き割り納豆.html", "num_path"=>5, "port"=>80}
    end
  end


  describe "parse url http://192.168.2.3/Public/home/fonts/glyphicons-halflings-regular.eot?" do
    config STDCONF
    
    event = { "source_url" => "http://192.168.2.3/Public/home/fonts/glyphicons-halflings-regular.eot?" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/Public/home/fonts/glyphicons-halflings-regular.eot", "filename"=>"glyphicons-halflings-regular.eot", "num_path"=>4, "querystring"=>"", "host"=>{"addr"=>{"ip"=>"192.168.2.3", "ipv4"=>"192.168.2.3", "port"=>80}}}
    end
  end

  describe "parse url http://3pjtx0jj-zxis6jz8.netdna-ssl.com/t.ashx?e=QHucCbLl+/brPsk3N17xhG4m/1fBfDFfAZx7JfD/ZiOJSpJdq6tfQE/IV6ft2BimupF1XXIOgnBEfC15jqNt2RHqxF5NXsoLYCpHZc9ZUaGLbhvor/ikhRQC+drCF7eFysWDrahxHN2vlPqRFoxtDu0Xbai9dKJl31YkSVL5i4AgQs72aFB5oJ8rnD0zDzgS" do
    config STDCONF
    
    event = { "source_url" => "http://3pjtx0jj-zxis6jz8.netdna-ssl.com/t.ashx?e=QHucCbLl+/brPsk3N17xhG4m/1fBfDFfAZx7JfD/ZiOJSpJdq6tfQE/IV6ft2BimupF1XXIOgnBEfC15jqNt2RHqxF5NXsoLYCpHZc9ZUaGLbhvor/ikhRQC+drCF7eFysWDrahxHN2vlPqRFoxtDu0Xbai9dKJl31YkSVL5i4AgQs72aFB5oJ8rnD0zDzgS" }
    #TODO: It's not clear how to split this URL up
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"3pjtx0jj-zxis6jz8.netdna-ssl.com", "path"=>"/t.ashx", "filename"=>"t.ashx", "num_path"=>1, "querystring"=>"e=QHucCbLl /brPsk3N17xhG4m/1fBfDFfAZx7JfD/ZiOJSpJdq6tfQE/IV6ft2BimupF1XXIOgnBEfC15jqNt2RHqxF5NXsoLYCpHZc9ZUaGLbhvor/ikhRQC drCF7eFysWDrahxHN2vlPqRFoxtDu0Xbai9dKJl31YkSVL5i4AgQs72aFB5oJ8rnD0zDzgS", "query"=>[{:parameter=>"e", :values=>["QHucCbLl /brPsk3N17xhG4m/1fBfDFfAZx7JfD/ZiOJSpJdq6tfQE/IV6ft2BimupF1XXIOgnBEfC15jqNt2RHqxF5NXsoLYCpHZc9ZUaGLbhvor/ikhRQC drCF7eFysWDrahxHN2vlPqRFoxtDu0Xbai9dKJl31YkSVL5i4AgQs72aFB5oJ8rnD0zDzgS"]}], "num_query"=>1}
    end
  end

  describe "parse url http://192.168.2.2/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/2/GJ3?public&code=9734c07b688b9b0f93d49edb366f9d62" do
    config STDCONF
    
    event = { "source_url" => "http://192.168.2.2/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/2/GJ3?public&code=9734c07b688b9b0f93d49edb366f9d62" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "path"=>"/fsintf/c9f2549fce18f4dc4ae13d6a6527d9c4e/2/GJ3", "filename"=>"GJ3", "num_path"=>4, "querystring"=>"public&code=9734c07b688b9b0f93d49edb366f9d62", "query"=>[{:parameter=>"public", :values=>[]}, {:parameter=>"code", :values=>["9734c07b688b9b0f93d49edb366f9d62"]}], "num_query"=>2, "host"=>{"addr"=>{"ip"=>"192.168.2.2", "ipv4"=>"192.168.2.2", "port"=>80}}}
    end
  end

    describe "parse url http://cm.example.com/cm/user?cm_tc&time=1429548780&domain=yy.com&zds=_736e7fd@yy|_e3d75f1@yy|www@yy|&hiido_ui=0.6427608964783057" do
    config STDCONF
    
    event = { "source_url" => "http://cm.example.com/cm/user?cm_tc&time=1429548780&domain=yy.com&zds=_736e7fd@yy|_e3d75f1@yy|www@yy|&hiido_ui=0.6427608964783057" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"cm.example.com", "path"=>"/cm/user cm_tc&time=1429548780&domain=yy.com&zds=_736e7fd yy _e3d75f1 yy www yy &hiido_ui=0.6427608964783057", "filename"=>"user cm_tc&time=1429548780&domain=yy.com&zds=_736e7fd yy _e3d75f1 yy www yy &hiido_ui=0.6427608964783057", "num_path"=>2}
    end
  end
  
    describe "parse url http://oq.example.com/stat.htm?id=30008588&r=&lg=en-us&ntime=none&cnzz_eid=627897484-1429520205-&showp=1024x768&t=undefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefined...&h=1&rnd=2068194930" do
    config STDCONF
    
    event = { "source_url" => "http://oq.example.com/stat.htm?id=30008588&r=&lg=en-us&ntime=none&cnzz_eid=627897484-1429520205-&showp=1024x768&t=undefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefined...&h=1&rnd=2068194930" }
    sample event do
      insist { subject["dest_url"] } == {"scheme"=>"http", "port"=>80, "hostname"=>"oq.example.com", "path"=>"/stat.htm", "filename"=>"stat.htm", "num_path"=>1, "querystring"=>"id=30008588&r=&lg=en-us&ntime=none&cnzz_eid=627897484-1429520205-&showp=1024x768&t=undefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefined...&h=1&rnd=2068194930", "query"=>[{:parameter=>"id", :values=>["30008588"]}, {:parameter=>"r", :values=>[]}, {:parameter=>"lg", :values=>["en-us"]}, {:parameter=>"ntime", :values=>["none"]}, {:parameter=>"cnzz_eid", :values=>["627897484-1429520205-"]}, {:parameter=>"showp", :values=>["1024x768"]}, {:parameter=>"t", :values=>["undefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefinedundefined..."]}, {:parameter=>"h", :values=>["1"]}, {:parameter=>"rnd", :values=>["2068194930"]}], "num_query"=>9}
    end
  end

    describe "parse url http://pomocnik_tso.republika.pl/wersja.ini" do
    config STDCONF    
    event = { "source_url" => "http://pomocnik_tso.republika.pl/wersja.ini" }
    sample event do
      insist { subject["dest_url"] } == {}
    end
  end

end
