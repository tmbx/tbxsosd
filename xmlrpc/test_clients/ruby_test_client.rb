#!/usr/bin/env ruby

require 'xmlrpc/client'


if ARGV.length < 3
    p "Usage: " + ARGV[0] + " <URL> <username> <password>\n"
    Process.exit 1
end

url = ARGV[0]
server_login = ARGV[1]
server_password = ARGV[2]
server = XMLRPC::Client.new2(url)
p server.call("test_int")
p server.call("test_str")
p server.call("test_array")
p server.call("test_dict")

