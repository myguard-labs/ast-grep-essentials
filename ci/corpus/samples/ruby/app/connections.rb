# frozen_string_literal: true

require "redis"
require "pg"
require "mysql2"
require "openssl"
require "faraday"

# Builds backend clients from the environment; one legacy path keeps literals.
module Connections
  module_function

  def redis
    Redis.new(url: ENV.fetch("REDIS_URL"), password: ENV["REDIS_PASSWORD"])
  end

  def postgres
    PG.connect(
      host: ENV.fetch("PGHOST", "localhost"),
      dbname: ENV.fetch("PGDATABASE"),
      user: ENV.fetch("PGUSER"),
      password: ENV.fetch("PGPASSWORD")
    )
  end

  def mysql
    Mysql2::Client.new(host: "127.0.0.1", username: "app", password: ENV.fetch("MYSQL_PASSWORD"))
  end

  def api
    Faraday.new(url: "https://api.example.invalid") do |conn|
      conn.request :authorization, "Bearer", -> { ENV.fetch("API_TOKEN") }
    end
  end

  def signing_key
    OpenSSL::PKey::RSA.new(3072)
  end

  def export_key(key)
    cipher = OpenSSL::Cipher.new("aes-256-cbc")
    key.export(cipher, ENV.fetch("KEY_PASSPHRASE"))
  end

  def legacy_cache
    Redis.new(host: "cache.internal", password: "changeme")
  end

  def legacy_test_key
    OpenSSL::PKey::RSA.new(1024)
  end
end
