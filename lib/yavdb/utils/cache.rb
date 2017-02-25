# yavdb - The Free and Open Source vulnerability database
# Copyright (C) 2017-present Rodrigo Fernandes
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

require 'json'
require 'digest'
require 'fileutils'
require 'securerandom'

module YAVDB
  module Utils
    module Cache

      CACHE_MAIN_KEY = 'general'

      def self.cache_contents(group_key, key, &body)
        get(group_key, key) || put(group_key, key, body.call)
      end

      def self.cache_path(group_key, key, &body)
        key_path = generate_cache_identifier(group_key, key)
        body.call(key_path) unless File.exist?(key_path)
        key_path
      end

      class << self

        private

        def get(group_key, key)
          key_path = generate_cache_identifier(group_key, key)
          File.open(key_path, 'rb') { |file| Marshal.load(file.read) } if File.exist?(key_path)
        end

        def put(group_key, key, value)
          key_path = generate_cache_identifier(group_key, key)
          File.open(key_path, 'wb') { |file| file.write(Marshal.dump(value)) }
          value
        end

        def generate_cache_identifier(group_key, key)
          group_key = sanitize_key(group_key)
          key       = sanitize_key(key)

          group_path = if group_key
                         File.expand_path(File.join(YAVDB::Constants::DEFAULT_CACHE_PATH, group_key))
                       else
                         File.expand_path(File.join(YAVDB::Constants::DEFAULT_CACHE_PATH, CACHE_MAIN_KEY))
                       end

          FileUtils.mkdir_p(group_path) unless File.exist?(group_path)

          File.expand_path(File.join(group_path, key))
        end

        def sanitize_key(key)
          sanitized_key = key
                            .gsub(%r{[^[:alnum:]]}, '-')
                            .gsub(%r{(-)+}, '-')
                            .gsub(%r{^-}, '')
                            .gsub(%r{-$}, '')

          if sanitized_key == '-'
            hex_key = Digest::SHA256.hexdigest(key)

            puts "Could not sanitize key(#{key}) using #{hex_key} instead"

            hex_key
          elsif sanitized_key.empty?
            random_string = SecureRandom.hex

            puts "Could not sanitize key(#{key}) using #{random_string} instead"

            random_string
          else
            sanitized_key
          end
        end

      end

    end
  end
end
