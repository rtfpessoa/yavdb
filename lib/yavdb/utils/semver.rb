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
  module Utils
    module SemVer

      SEMANTIC_INTERVAL_REGEX = %r{([(\[].+?[)\]])}

      def self.clean_versions(versions)
        return if versions.nil? || (!versions.is_a?(String) && !versions.is_a?(Array))

        versions = to_array(versions).map do |version|
          if semantic_interval?(version)
            convert_to_semver(version)
          else
            split_versions(version)
          end
        end

        versions
          .flatten
          .map(&:strip)
          .select { |str| str != '-' && !str.empty? }
      end

      class << self

        private

        def to_array(versions)
          versions = [versions] if versions.is_a?(String)

          versions
            .flatten
            .reject { |str| str.strip.empty? }
        end

        def semantic_interval?(version)
          version =~ SEMANTIC_INTERVAL_REGEX
        end

        def convert_to_semver(version)
          ver_tmp = version
                      .scan(SEMANTIC_INTERVAL_REGEX)
                      .flatten
                      .map { |v| SemanticInterval.parse(v) }

          if ver_tmp.any?
            ver_tmp
          else
            version
          end
        end

        def split_versions(version)
          version
            .strip
            .split(/,|\|\|/)
        end

      end

    end
  end
end
