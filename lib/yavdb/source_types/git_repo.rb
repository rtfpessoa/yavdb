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

require_relative '../utils/git'

module YAVDB
  module SourceTypes
    module GitRepo

      def self.search(file_pattern, repo_url, repo_branch = 'master', with_cache = true)
        repo_path = YAVDB::Utils::Git.get_contents(repo_url, repo_branch, with_cache)

        file_paths = Dir.chdir(repo_path) do
          Dir.glob(file_pattern).select { |f| File.file?(f) }
        end

        Hash[repo_path => file_paths]
      end

    end
  end
end
