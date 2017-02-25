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

require 'net/http'
require 'socket'
require 'yaml'
require 'semantic_interval'
require 'oga'
require 'oga/xml/entities'

require_relative 'yavdb/constants'
require_relative 'yavdb/crawler'
require_relative 'yavdb/database'
require_relative 'yavdb/utils/exec'
require_relative 'yavdb/utils/http'
require_relative 'yavdb/utils/git'

module YAVDB
  class API

    # List vulnerabilities from database_path of package_name for package_manager.
    #
    # @param package_manager [String] the package manager.
    # @param package_name [String] the package_name.
    # @param database_path [String] the local path to the database.
    # @return [Array<Advisory>] the array of vulnerabilities.
    def self.list_vulnerabilities(package_manager,
      package_name,
      database_path = YAVDB::Constants::DEFAULT_YAVDB_PATH)
      YAVDB::Database.search(database_path, package_manager, package_name)
    end

    # Crawl several sources and generate a local database in database_path.
    #
    # @param database_path [String] the local path to the database.
    def self.generate_database(database_path = YAVDB::Constants::DEFAULT_GENERATE_DATABASE_PATH)
      vulnerabilities = YAVDB::Crawler.vulnerabilities
      YAVDB::Database.save(database_path, vulnerabilities)
    end

    # Download a previously generated database from the official yavdb repository into yavdb_path.
    #
    # @param force_update [Boolean] force an update of the database if it already exists but is in a previous version.
    # @param yavdb_path [String] the local path to the yavdb repository with the database.
    # @param yavdb_url [String] the yavdb url to clone the database repository from.
    # @param yavdb_branch [String] the yavdb branch with the database.
    def self.download_database(force_update = false,
      yavdb_path = YAVDB::Constants::DEFAULT_YAVDB_PATH,
      yavdb_url = YAVDB::Constants::YAVDB_DB_URL,
      yavdb_branch = YAVDB::Constants::YAVDB_DB_BRANCH)
      YAVDB::Utils::Git.download_or_update(yavdb_path, yavdb_url, yavdb_branch, force_update)
    end

  end
end
