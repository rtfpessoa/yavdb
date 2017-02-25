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

require 'thor'

require_relative 'constants'
require_relative '../yavdb'

module YAVDB
  class CLI < Thor

    map '--version' => :version

    class_option('verbose', :type => :boolean, :default => false)

    method_option('package-manager', :alias => :m, :type => :string, :required => true)
    method_option('package-name', :alias => :n, :type => :string, :required => true)
    method_option('database-path', :type => :string, :aliases => :p, :default => YAVDB::Constants::DEFAULT_YAVDB_DATABASE_PATH)
    desc('list', 'List vulnerabilities from database-path of package-name for package-manager.')

    def list
      package_manager = options['package-manager']

      unless YAVDB::Constants::POSSIBLE_PACKAGE_MANAGERS.include?(package_manager)
        puts "Package manager #{package_manager} is not supported yet."
        exit(1)
      end

      API.list_vulnerabilities(package_manager, options['package-name'], options['database-path'])
    end

    method_option('database-path', :type => :string, :aliases => :p, :default => YAVDB::Constants::DEFAULT_GENERATE_DATABASE_PATH)
    desc('generate', 'Crawl several sources and generate a local database in database-path.')

    def generate
      API.generate_database(options['database-path'])
    end

    method_option('yavdb-path', :type => :string, :aliases => :p, :default => YAVDB::Constants::DEFAULT_YAVDB_PATH)
    desc('download', 'Download a previously generated database from the official yavdb repository into yavdb-path.')

    def download
      API.download_database(options['yavdb-path'])
    end

  end
end
