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

require 'tmpdir'

require_relative '../constants'
require_relative '../utils/exec'
require_relative '../utils/cache'

module YAVDB
  module Utils
    module Git

      def self.get_contents(repo_url, repo_branch, with_cache = true, group_cache_key = 'git')
        puts "Requesting #{repo_url}" if Constants::DEBUG

        if with_cache
          YAVDB::Utils::Cache.cache_path(group_cache_key, repo_url) do |repo_path|
            download_or_update(repo_path, repo_url, repo_branch)
            repo_path
          end
        else
          repo_path = Dir.mktmpdir(group_cache_key)
          download_or_update(repo_path, repo_url, repo_branch)
          repo_path
        end
      end

      def self.download_or_update(repo_path, repo_url, repo_branch, force_update = true)
        puts "Downloading #{repo_url}" if Constants::DEBUG

        if File.exist?(repo_path) && Dir.entries(repo_path) != ['.', '..']
          if File.directory?(File.expand_path(File.join(repo_path, '.git')))
            Dir.chdir(repo_path) do
              YAVDB::Utils::Executor.run("git fetch --all && git reset --hard origin/#{repo_branch}") if force_update
            end
          else
            puts "Repository directory already exists and is not a valid git repository in #{repo_path}"
            exit(1)
          end
        else
          YAVDB::Utils::Executor.run("git clone #{repo_url} -b #{repo_branch} #{repo_path}")
        end
      end

    end
  end
end
