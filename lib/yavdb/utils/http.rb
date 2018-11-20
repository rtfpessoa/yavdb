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

require 'net/https'

require_relative '../utils/cache'

module YAVDB
  module Utils
    module HTTP

      def self.get_page_contents(url, with_cache = true, group_cache_key = 'http')
        puts "Requesting #{url}"

        if with_cache
          YAVDB::Utils::Cache.cache_contents(group_cache_key, url) { do_request(url) }
        else
          do_request(url)
        end
      end

      class << self

        private

        def do_request(url)
          puts "Fetching #{url}"

          url = URI.parse(url)
          retries ||= 3

          begin
            response = Net::HTTP.get_response(url)
            case response
              when Net::HTTPNotFound then
                raise ArgumentError, 'page not found'
              when Net::HTTPTooManyRequests then
                raise ArgumentError, 'too many requests'
              else
                response.body.lines
            end
          rescue StandardError => exception
            raise exception if retries.zero?

            puts "Going to retry #{url}"
            retries -= 1
            sleep(5)
            retry
          end
        end

      end

    end
  end
end
