#!/bin/env ruby

require 'openssl'
require 'base64'
require 'net/http'
require 'hmac-sha2'
require 'date'
require 'builder'
require 'libxml'
require 'json'
require 'thread'
require 'fileutils'
require 'pathname'

Config={}

def account(account)
  Config[:Account] = account
end

def key(key)
  Config[:Key] = key
end

def container(container)
  Config[:Container] = container
end

load("storage.config", true)


def canonicalizedHeaders(request)
  canonicalizedHeaders = {}
    
  request.each_header do |key,value|
    key = key.downcase.strip
    value = value.strip

    canonicalizedHeaders[key] = value if key.start_with?("x-ms-")
  end
  
  canonicalizedHeaders.sort.map do |item|
    item.join(":") + "\n"
  end.join
end

def canonicalizedResource(request, account)
  uri = URI.parse(request.path)
  el = []
  el << "/#{account}#{uri.path}"
  URI.decode_www_form(uri.query).sort.each do |item|
    el << item.join(":")
  end

  el.join("\n")
end

def sign_blob_request(request, account, key)
  request['x-ms-date'] = DateTime.now.httpdate unless not request['Date'].nil? and not request['x-ms-date'].nil?
  request['Content-Length'] ||= request.body.length unless request.body.nil?
  request['x-ms-version'] = '2009-09-19'
  
  toSign = "#{request.method}\n" +
           "#{request['Content-Encoding']}\n" +
           "#{request['Content-Language']}\n" +
           "#{request['Content-Length']}\n" +
           "#{request['Content-MD5']}\n" +
           "#{request['Content-Type']}\n" +
           "#{request['Date']}\n" +
           "#{request['If-Modified-Since']}\n" +
           "#{request['If-Match']}\n" + 
           "#{request['If-None-Match']}\n" +
           "#{request['If-Unmodified-Since']}\n" +
           "#{request['Range']}\n" +
           "#{canonicalizedHeaders(request)}" +
           "#{canonicalizedResource(request, account)}"

  token = Base64.strict_encode64(HMAC::SHA256.digest(Base64.decode64(key), toSign))
  request['authorization'] = "SharedKey %s:%s" % [account, token]
end

class Enum
  private
  def self.enum_attr(name, num)
    name = name.to_s

    define_method(name + '?') do
      @attrs & num != 0
    end

    define_method(name + '=') do |set|
      if set
        @attrs |= num
      else
        @attrs &= ~num
      end
    end
  end

  public

  def initialize(attrs = 0)
    @attrs = attrs
  end

  def to_i
    @attrs
  end
end

class Blob
  @path
  @blocks
  @dlStateFile
  
  attr_accessor :path, :blocks
  
  def initialize(path)
    @path = path
    @blocks = {}
    @blockQueue = Queue.new
    @blocksNeedCommit = false
    @dlStateFile = @path + ".blobdl/state.json"
    @mutex = Mutex.new
    
    check_status
  end
  
  def check_status
    # here we ask the blobstorage which blocks are present
    # and create the blobblocks acordently
    
    # We have a full file downloaded
    if File.exist? @path
      # We also got the blobdl folder, this
      # is just a leftover, so remove it
      if File.directory? @path + ".blobdl"
        FileUtils.remove_dir(@path + ".blobdl")
      end
      
      size = File.size(@path)
      Range.new(0, size).step(BlobBlock::BlockSize) do |n|
        b = BlobBlock.new(@path, n/BlobBlock::BlockSize)
        b.state.local = true
        
        @blocks[b.blockID] = b
      end

      puts "Checking uploaded blocks..."
      get_remote_blocklist
      
      @blocks.each do |name,block|
        if not block.state.uploaded?
          @blockQueue << block
        end
        if not block.state.commited?
          @blocksNeedCommit = true
        end
      end
      
      puts "#{@blockQueue.length} blocks need to be uploaded." unless @blockQueue.empty?
      puts "Need to commit blocks" if @blocksNeedCommit
      
      do_blocks
      
      if @blocksNeedCommit
        puts "Commit blocks..."
        put_remote_blocklist
      end
      
      puts "All done :)"
    # File does not exist yet, so we're downloading
    else      
      puts "Reading remote blocklist..."
      get_remote_blocklist
      
      raise "Online file not found" if @blocks.empty?
      
      Dir.mkdir @path + ".blobdl" unless File.directory? @path + ".blobdl"
      
      read_dl_state
      
      @blocks.each do |name, block|
        @blockQueue << block unless block.state.local?
      end
      
      puts "Need to get #{@blockQueue.length}/#{@blocks.length} blocks..." unless @blockQueue.empty?

      do_blocks unless @blockQueue.empty?
      
      File.rename(@path + ".blobdl/data", @path)
      FileUtils.remove_dir(@path + ".blobdl")
    end
  end
  
  def read_dl_state
    if File.exist? @dlStateFile
      json = nil
      
      open(@dlStateFile) do |f|
        json = JSON.load(f)
      end
      
      json['complete'].each do |name|
        @blocks[name].state.local = true
      end
    end
  end
  
  def write_dl_state
    @mutex.synchronize do
      json = { 'complete' => []}
    
      @blocks.each do |name,block|
        json['complete'] << name if block.state.local?
      end
    
      open(@dlStateFile, "w") do |f|
        JSON.dump(json, f)
      end
    end
  end
  
  def get_remote_blocklist
    request = Net::HTTP::Get.new((BlobBlock.buildBlobPath(@path, {:comp => "blocklist", :blocklisttype => "all"})))

    sign_blob_request(request, Config[:Account], Config[:Key])
    response = Net::HTTP.new("#{Config[:Account]}.blob.core.windows.net").request(request)
    
    # Nothing uploaded yet
    if response.code.to_i == 404
      # do nothing :)
    elsif not (200..299).include?(response.code.to_i)
      puts "Error #{response.code}"
      p response.body
      raise "Error"
    else
      listener = Class.new do
        include LibXML::XML::SaxParser::Callbacks
        
        def initialize(blob)
          @blob = blob
        end
        
        def on_start_element(name, attr_hash)
          if name == "Name"
            @blockName = ""
          elsif name == "CommittedBlocks"
            @state = :commited
          elsif name == "UncommittedBlocks"
            @state = :uncommited
          end
        end

        def on_characters( str )
          @blockName += str unless @blockName.nil?
        end

        def on_end_element(name)
          if name == "Name"
            if @blob.blocks[@blockName].nil? and not @state == :uncommited
              @blob.blocks[@blockName] = BlobBlock.new(@blob.path, BlobBlock.numberFromBlockID(@blockName))
            end
            
            if not @blob.blocks[@blockName].nil?
              if @state == :commited
                @blob.blocks[@blockName].state.remote = true
              elsif @state == :uncommited
                @blob.blocks[@blockName].state.uploaded = true
              end
            end
          end
        end
      end.new(self)
        
      parser = LibXML::XML::SaxParser.string(response.body)
      parser.callbacks = listener
      parser.parse
    end
  end
  
  def put_remote_blocklist
    request = Net::HTTP::Put.new((BlobBlock.buildBlobPath(@path, {:comp => "blocklist"})))
    request['Content-Type'] = "text/plain; charset=UTF-8"
    
    request.body = ""
    
    xml = Builder::XmlMarkup.new({ :indent => 2, :target => request.body})
    
    xml.instruct!
    xml.BlockList do |list|
      @blocks.each do |name, block|
        list.Latest "#{name}"
      end
    end
    
    p request.path
    sign_blob_request(request, Config[:Account], Config[:Key])
    response = Net::HTTP.new("#{Config[:Account]}.blob.core.windows.net").request(request)
    
    if not (200..299).include?(response.code.to_i)
      puts "Error #{response.code}"
      p response.body
      raise "Error"
    end
    
    p response.body
    response
  end
  
  def do_blocks
    @threads = []
    
    2.times do
      @threads << Thread.new do
        work_blocks
      end
    end
    
    @threads.each do |thread|
      thread.join
    end
  end
  
  def work_blocks
    begin
      while true do
        block = @blockQueue.pop(true)
        
        if not block.state.local?
          block.getBlock
          write_dl_state
        end
        block.putBlock unless block.state.uploaded?
        
      end
    rescue ThreadError
    end
  end
end

class BlobBlock
  BlockSize = 512 * 1024 # 512 kb
  
  class State < Enum
    enum_attr :local, 0x1
    enum_attr :uploaded, 0x2
    enum_attr :commited, 0x4
    enum_attr :remote, 0x6
  end
  
  @state
  @number # is the sequential number begining with 0 (offset in file is @number * blocksize)
  @size # is <= BlobBlock::BlockSize,
  # if smaler than blocksize it's guranteed to be the last block
  # but it may also be the last block when @size == BlobBlock::BlockSize
  @path
  @buffer
  @md5
  @http_connection
  
  attr_accessor :number, :size, :state
  
  def self.buildBlobPath(path, query)
    "/#{Config[:Container]}/#{Pathname.new(path).basename}?#{URI.encode_www_form(query)}"
  end
  
  def self.numberFromBlockID(blockID)
    Base64.decode64(blockID).to_i
  end
  
  def initialize(path, number, size=BlockSize)
    @state = State.new
    @path = path
    @number = number
    @size = size
    @http_connection = Net::HTTP.new("#{Config[:Account]}.blob.core.windows.net")
  end
  
  def loadBlockToMemory
    open(@path, "r") do |f|
      f.seek(@number * BlockSize)
      @buffer = f.read(@size)
      @size = @buffer.length
    end
    
    @md5 = Base64.strict_encode64(OpenSSL::Digest::MD5.digest(@buffer))
  end
  
  def blockID
    Base64.strict_encode64("%010d" % @number)
  end
  
  def putBlock
    puts "Upload ##{@number}..."
    
    loadBlockToMemory
    
    request = Net::HTTP::Put.new(BlobBlock.buildBlobPath(@path, {:comp => "block", :blockid => self.blockID}))
    request['Content-Type'] = "application/octet-stream"
    request['Content-MD5'] = @md5
    request.body = @buffer
    
    response = sendRequest!(request)
    
    @state.uploaded = true
    @buffer = nil
  end
  
  def getBlock
    puts "Download ##{@number}..."
    
    request = Net::HTTP::Get.new(BlobBlock.buildBlobPath(@path, {}))
    request['Range'] = "bytes=#{@number * BlockSize}-#{@number * BlockSize + @size}"
        
    response = sendRequest!(request)
    
    IO::write(@path + ".blobdl/data", response.body, @number * BlockSize)
    
    @state.local = true
  end
  
  def sendRequest!(request)
    sign_blob_request(request, Config[:Account], Config[:Key])
    response = @http_connection.request(request)
    
    if not (200..299).include?(response.code.to_i)
      puts "Error #{response.code}"
      p response.body
      raise "Error"
    end
    
    response
  end
end

raise "need name" if ARGV[0].nil?

Blob.new ARGV[0]