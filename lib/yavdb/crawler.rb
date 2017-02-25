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

Dir[File.expand_path('sources/*.rb', __dir__)].each do |file|
  require file
end

module YAVDB
  class Crawler

    def self.sources
      YAVDB::Sources.constants
        .map { |c| YAVDB::Sources.const_get(c) }
        .sort_by { |c| c.to_s.downcase }
    end

    def self.vulnerabilities
      vulns = sources.map { |src| src::Client.advisories }.flatten
      clean_vulnerability_versions(vulns)
    end

    class << self

      private

      def clean_vulnerability_versions(vulnerabilities)
        vulnerabilities
          .map do |vln|
          vln.vulnerable_versions = YAVDB::Utils::SemVer.clean_versions(vln.vulnerable_versions)
          vln.unaffected_versions = YAVDB::Utils::SemVer.clean_versions(vln.unaffected_versions)
          vln.patched_versions    = YAVDB::Utils::SemVer.clean_versions(vln.patched_versions)
          vln
        end
      end

    end

  end
end
