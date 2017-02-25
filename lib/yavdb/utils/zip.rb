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

require 'fileutils'

require_relative '../constants'
require_relative '../utils/cache'
require_relative '../utils/exec'

module YAVDB
  module Utils
    module Zip

      def self.get_contents(zip_url, with_cache = true, group_cache_key = 'zip')
        puts "Requesting #{zip_url}" if Constants::DEBUG

        if with_cache
          YAVDB::Utils::Cache.cache_path(group_cache_key, zip_url) do |zip_path|
            do_request(zip_path, zip_url)
            zip_path
          end
        else
          zip_path = Dir.mktmpdir(group_cache_key)
          do_request(zip_path, zip_url)
          zip_path
        end
      end

      class << self

        private

        def do_request(zip_path, zip_url)
          puts "Downloading #{zip_url}" if Constants::DEBUG

          resource_path = "#{zip_path}/resource.zip"

          FileUtils.rm_rf(zip_path)
          FileUtils.mkdir_p(zip_path)

          YAVDB::Utils::Executor.run %(wget -O #{resource_path} #{zip_url})
          YAVDB::Utils::Executor.run %(unzip #{resource_path} -d #{zip_path})

          FileUtils.rm(resource_path)
        end

      end

    end
  end
end
