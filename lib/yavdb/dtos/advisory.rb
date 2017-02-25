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
  # TODO: Enable `Style/StructInheritance` - check `attr_reader:` or `initialize` method
  class Advisory <

    Struct.new(
      :id, # [String]
      :title, # [String]
      :description, # [String]
      :affected_package, # [String]
      :vulnerable_versions, # [Array<String>] (Optional)
      :unaffected_versions, # [Array<String>] (Optional)
      :patched_versions, # [Array<String>] (Optional)
      :severity, # [String] (Optional)
      :package_manager, # [String]
      :cve, # [Array<String>] (Optional)
      :cwe, # [Array<String>] (Optional)
      :osvdb, # [String] (Optional)
      :cvss_v2_vector, # [String] (Optional)
      :cvss_v2_score, # [String] (Optional)
      :cvss_v3_vector, # [String] (Optional)
      :cvss_v3_score, # [String] (Optional)
      :disclosed_date, # [Date]
      :created_date, # [Date]
      :last_modified_date, # [Date]
      :credit, # [Array<String>]
      :references, # [Array<String>]
      :source_url # [String]
    )

    def self.load(path)
      data = YAML.load_file(path)

      raise("Advisory data in #{path.dump} was not an Array") unless data.is_a?(Array)

      data.map do |advisory|
        raise("Advisory data in #{path.dump} was not a Hash") unless advisory.is_a?(Hash)

        new(
          advisory['id'],
          advisory['title'],
          advisory['description'],
          advisory['affected_package'],
          advisory['vulnerable_versions'],
          advisory['unaffected_versions'],
          advisory['patched_versions'],
          advisory['severity'],
          advisory['package_manager'],
          advisory['cve'],
          advisory['cwe'],
          advisory['osvdb'],
          advisory['cvss_v2_vector'],
          advisory['cvss_v2_score'],
          advisory['cvss_v3_vector'],
          advisory['cvss_v3_score'],
          advisory['disclosed_date'],
          advisory['created_date'],
          advisory['last_modified_date'],
          advisory['credit'],
          advisory['references'],
          advisory['source_url']
        )
      end
    end

    def to_map
      map = {}
      members.each do |m|
        next unless self[m] && (
        (self[m].is_a?(String) && !self[m].empty?) ||
          (self[m].is_a?(Array) && self[m].any?))

        map[m.to_s] = self[m] if self[m]
      end
      map
    end

    def to_json(*args)
      to_map.to_json(*args)
    end

    def to_yaml(*args)
      to_map.to_yaml(*args)
    end

  end
end
