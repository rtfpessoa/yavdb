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

require_relative 'spec_helper'

require 'yavdb/sources/nodesecurity_io'

RSpec.describe YAVDB::Sources::NodeSecurityIO::Client do
  vulns = YAVDB::Sources::NodeSecurityIO::Client.send(:fetch_advisories)

  describe 'fetch_advisories' do
    it 'should have the required properties' do
      expect(vulns).to all(have_key('publish_date'))
      expect(vulns).to all(have_key('created_at'))
      expect(vulns).to all(have_key('updated_at'))
      expect(vulns).to all(have_key('vulnerable_versions'))
      expect(vulns).to all(have_key('module_name'))
      expect(vulns).to all(have_key('title'))
      expect(vulns).to all(have_key('overview'))
      expect(vulns).to all(have_key('patched_versions'))
      expect(vulns).to all(have_key('cvss_score'))
      expect(vulns).to all(have_key('cves'))
      expect(vulns).to all(have_key('cvss_vector'))
      expect(vulns).to all(have_key('cvss_score'))
      expect(vulns).to all(have_key('author'))
      expect(vulns).to all(have_key('references'))
      expect(vulns).to all(have_key('id'))
    end
  end

  describe 'create' do
    advisories = vulns.map do |advisory_hash|
      YAVDB::Sources::NodeSecurityIO::Client.send(:create, advisory_hash)
    end

    it 'should have the required properties' do
      expect(advisories).to all(have_attributes(:id => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:title => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:description => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:affected_package => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:vulnerable_versions => an_instance_of(Array)))
      # expect(advisories).to all(have_attributes(:unaffected_versions => an_instance_of(Array)))
      # expect(advisories).to all(have_attributes(:patched_versions => an_instance_of(Array)))
      # expect(advisories).to all(have_attributes(:severity => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:package_manager => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:cve => an_instance_of(Array)))
      # expect(advisories).to all(have_attributes(:cwe => an_instance_of(Array)))
      # expect(advisories).to all(have_attributes(:cvss_v2_vector => an_instance_of(String)))
      # expect(advisories).to all(have_attributes(:cvss_v2_score => an_instance_of(String)))
      # expect(advisories).to all(have_attributes(:cvss_v3_vector => an_instance_of(String)))
      # expect(advisories).to all(have_attributes(:cvss_v3_score => an_instance_of(String)))
      expect(advisories).to all(have_attributes(:disclosed_date => an_instance_of(Date)))
      expect(advisories).to all(have_attributes(:created_date => an_instance_of(Date)))
      expect(advisories).to all(have_attributes(:last_modified_date => an_instance_of(Date)))
      expect(advisories).to all(have_attributes(:credit => an_instance_of(Array)))
      expect(advisories).to all(have_attributes(:references => an_instance_of(Array)))
      expect(advisories).to all(have_attributes(:source_url => an_instance_of(String)))
    end
  end
end
