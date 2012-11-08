#!/usr/bin/env ruby

# Copyright (c) 2012, Christian Speich <christian@spei.ch>
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

require 'Net/HTTP'
require 'rexml/document'

class SOAPClient
  @@ServiceURL = "http://azuremd2.cloudapp.net/Service1.svc"
  @soapAction = nil
  @soapName = nil
  
  def loadWSDL()
    response = Net::HTTP.get_response(URI.parse(@@ServiceURL + "?wsdl"))
    
    doc = REXML::Document.new(response.body)
    @soapAction = REXML::XPath.first(doc, "//soap:operation/@soapAction")
    @soapName = REXML::XPath.first(doc, "//wsdl:operation/@name")
  end
  
  def soapRequestForAction()
    request = <<EOF
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Header>
    <password xmlns="http://tempuri.org">geheim</password>
  </s:Header>
  <s:Body>
    <%{action} xmlns="http://tempuri.org/"></%{action}>
  </s:Body>
</s:Envelope>
EOF
  
    request % { action: @soapName }
  end
  
  def sendRequest()
    self.loadWSDL()
    
    http = Net::HTTP.new(URI.parse(@@ServiceURL).host)
    
    request = Net::HTTP::Post.new(URI.parse(@@ServiceURL).path)
    request.body = self.soapRequestForAction()
    request['Content-Type'] = "text/xml; charset=UTF-8"
    request['SOAPAction'] = @soapAction
    
    doc = REXML::Document.new(http.request(request).body)
    REXML::XPath.first(doc, "//GetTheSecretPhraseResult/text()")
  end
end

client = SOAPClient.new

puts client.sendRequest()