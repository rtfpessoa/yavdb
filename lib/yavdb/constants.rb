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

module YAVDB
  module Constants

    DEBUG = ENV['debug']

    YAVDB_DB_URL    = 'https://github.com/rtfpessoa/yavdb.git'
    YAVDB_DB_BRANCH = 'database'

    DEFAULT_GENERATE_DATABASE_PATH = File.expand_path(File.join(Dir.pwd, ['database'])).freeze

    DEFAULT_YAVDB_PATH          = File.expand_path(File.join(ENV['HOME'], '.yavdb', 'yavdb')).freeze
    DEFAULT_YAVDB_DATABASE_PATH = File.expand_path(File.join(DEFAULT_YAVDB_PATH, 'database')).freeze
    DEFAULT_CACHE_PATH          = File.expand_path(File.join(ENV['HOME'], '.yavdb', 'cache')).freeze

    POSSIBLE_PACKAGE_MANAGERS = ['npm', 'rubygems', 'maven', 'nuget', 'packagist', 'pypi', 'go', 'cargo'].freeze

    SEVERITIES = ['low', 'medium', 'high'].freeze

  end
end
