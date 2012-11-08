
require 'Base64'
require 'hmac-sha2'
require 'Net/HTTP'
require 'date'
require 'SecureRandom'
require 'builder'
require 'rexml/document'
require 'rexml/streamlistener'

#module Config
  @Account
  @Key
  @Table

  def account(account)
    @Account = account
  end

  def key(key)
    @Key = key
  end

  def table(table)
    @Table = table
  end

  load "storage.config"
#end

class AzureTable
  @authKey = nil
  @account = nil
  @table = nil
  @http = nil
  
  def initialize(authKey, account, table)
    @authKey = authKey
    @account = account
    @table = table
    @http = Net::HTTP.new(account + ".table.core.windows.net")
    @http.start
  end
  
  def sendPostRequest(body)
    request = Net::HTTP::Post.new("/" + @table)
    request['Content-Type'] = "application/atom+xml"
    request.body = body
    
    addAuthorizationToRequest(request)
    
    response = @http.request(request)
    
    if not (200..299).include?(response.code.to_i)
      puts "Error #{response.code} #{response.body}"
      raise "Error"
    end
    
    response
  end
  
  def sendGetRequest(args)
    request = Net::HTTP::Get.new("/" + @table + "?" + URI.encode_www_form(args))
    request['Content-Type'] = "application/atom+xml"
    
    addAuthorizationToRequest(request)
    
    response = @http.request(request)
    
    if not (200..299).include?(response.code.to_i)
      puts "Error #{response.code} #{response.body}"
      raise "Error"
    end
    
    response
  end
  
  def addAuthorizationToRequest(request)
    date = DateTime.now.httpdate

    toSign = "%{method}\n%{contentMD5}\n%{contentType}\n%{date}\n/%{account}%{resource}" % {
      method: request.method,
      contentMD5: "",
      contentType: request['Content-Type'],
      date: date,
      account: @account,
      resource: URI.parse(request.path).path
    }
    
    #impotant to use strict, or we get error 400 invalid host
    token = Base64.strict_encode64(HMAC::SHA256.digest(Base64.decode64(@authKey), toSign))
    
    request['x-ms-date'] = date
    request['authorization'] = "SharedKey %s:%s" % [@account, token]
  end
end

def authorizationToken(authKey, account, date, contentType, method, resource)
  toSign = "%{method}\n%{contentMD5}\n%{contentType}\n%{date}\n/%{account}/%{resource}" % {
    method: method,
    contentMD5: "",
    contentType: request['Content-Type'],
    date: date,
    account: account,
    resource: resource
  }
  puts toSign
  Base64.encode64(HMAC::SHA256.digest(Base64.decode64(authKey), toSign))
end

class EmployeesXMLListener
  include REXML::StreamListener
  attr_accessor :Employees
  
  def initialize
    @Employees = []
    @Employee = nil
    @value = ""
  end

  def tag_start(name, attr_hash)
    if name == "entry"
      @Employee = Employee.new(nil, true)
      @value = ""
    end
  end

  def text( str )
    @value += str
  end

  # Treat CDATA sections just like text
  alias_method :cdata, :text

  def tag_end( name )
    if name == "entry"
      @Employees << @Employee
      @Employee = nil
    end
    
    if not @Employee.nil?
      @value = @value.strip
      case name
      when "d:RowKey"
        @Employee.RowKey = @value
      when "d:Position"
        @Employee.Position = @value
      when "d:Timestamp"
        @Employee.Timestamp = DateTime.xmlschema(@value)
      when "d:Name"
        @Employee.Name = @value
      when "d:Address"
        @Employee.Address = @value
      when "d:Salary"
        @Employee.Salary = @value
      when "d:PartitionKey"
        a = @value.split("_PLZ")
        @Employee.Country = a[0]
        @Employee.ZipCode = a[1].to_i
      end
      @value = ""
    end
  end
end

class Employee
  Countries = ["USA", "UK", "Germany"]
  Positions = ["Developer", "Tester", "Manager"]
  
  @Country
  @ZipCode
  @RowKey
  @Timestamp
  @Name
  @Address
  @Salary
  @Position
  
  attr_accessor :Country, :ZipCode, :RowKey, :Timestamp, :Name, :Address, :Salary, :Position
  
  def self.employeesFromResponse(response)
    listener = EmployeesXMLListener.new
    
    REXML::Document.parse_stream(response.body, listener)
    
    listener.Employees
  end
  
  def self.nextIndex(country)
    nextIndex = 0
    
    file = "index-%s.txt" % country
    
    File.new(file, "w").close unless File.exist?(file)
    
    File.open(file, "r+") do |file|
      nextIndex = file.read.to_i
      file.rewind
      file.puts nextIndex + 1
    end
    
    nextIndex
  end
  
  def initialize(country = nil, empty = false)
    if not country.nil? and not empty
      raise "Need a country" if country.nil?
      raise "Bad country" unless Countries.include?(country)
      
      @RowKey = "%010d" % Employee.nextIndex(country)
      @Country = country
      @ZipCode = 1001 + rand(98998)
      @Timestamp = DateTime.now
      @Name = (0...8).map{65.+(rand(26)).chr}.join
      @Address = (0...8).map{65.+(rand(26)).chr}.join
      @Salary = 20000 + rand(80000)
      @Position = Positions[rand(Positions.length)]
    end
  end
  
  def partitionKey
    "%s_PLZ%05d" % [@Country, @ZipCode]
  end
  
  def to_xml
    xml = Builder::XmlMarkup.new( :indent => 2 )
    
    xml.instruct!
    xml.entry("xmlns:d" => "http://schemas.microsoft.com/ado/2007/08/dataservices", "xmlns:m" => "http://schemas.microsoft.com/ado/2007/08/dataservices/metadata", "xmlns"=>"http://www.w3.org/2005/Atom") do |entry|
      entry.title
      entry.updated DateTime.now.xmlschema
      entry.author do |a|
        a.name
      end
      entry.id
      
      entry.content("type" => "application/xml") do |content|
        content.m :properties do |d|
          d.tag!("d:Address", @Address)
          d.tag!("d:Name", @Name)
          d.tag!("d:Salary", @Salary)
          d.tag!("d:Position", @Position)
          d.tag!("d:PartitionKey", self.partitionKey)
          d.tag!("d:RowKey", @RowKey)
          d.tag!("d:Timestamp", @Timestamp.xmlschema)      
        end
      end
    end
  end
  
  def to_s
    "Employee(Country = #{@Country}, ZipCode = #{@ZipCode}, RowKey = #{@RowKey}, Timestamp = #{@Timestamp}, Name = #{@Name}, Address = #{@Address}, Salary = #{@Salary}, Position = #{@Position})"
  end
end

Table = AzureTable.new(@Key, @Account, @Table)

def printUsage
  puts "TableStorage.rb gen country count"
  puts "                read [country]"
end

def generateEntries(country, count)
  raise "Count must be greater zero" unless count > 0
  raise "Unkown country" unless Employee::Countries.include?(country)
  
  (1..count).each do |n|
    employee = Employee.new(country)
    puts "##{n}: Upload #{employee}"
    Table.sendPostRequest(employee.to_xml)
  end
end

def getEntries(country)
  raise "Unkown country" unless Employee::Countries.include?(country) or country.nil?
  
  continuationNextTableName = nil
  continuationNextPartitionKey = nil
  continuationNextRowKey = nil
  
  employees = []
  
  begin
    args = {}
    
    args['NextTableName'] ||= continuationNextTableName
    args['NextPartitionKey'] ||= continuationNextPartitionKey
    args['NextRowKey'] ||= continuationNextRowKey
    
    if not country.nil?
      args['$filter'] = "(PartitionKey ge '#{country}_PLZ00000') and (PartitionKey le '#{country}_PLZ99999')"
    end
    
    puts "Fetch..."
    response = Table.sendGetRequest(args)
    
    continuationNextTableName = response['x-ms-continuation-NextTableName']
    continuationNextPartitionKey = response['x-ms-continuation-NextPartitionKey']
    continuationNextRowKey = response['x-ms-continuation-NextRowKey']
    
    employees += Employee.employeesFromResponse(response)
  end while not (continuationNextTableName.nil? and continuationNextPartitionKey.nil? and continuationNextRowKey.nil?)
  
  puts "Found #{employees.length}"
end

if ARGV.length < 1
  printUsage
  exit! 1
end

case ARGV[0]
when "gen"
  if ARGV.length != 3
    printUsage
    exit! 1
  end
  generateEntries(ARGV[1], ARGV[2].to_i)
when "read"
  puts "read something"
  getEntries(ARGV[1])
end
