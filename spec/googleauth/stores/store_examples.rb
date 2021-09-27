# Copyright 2015 Google, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

spec_dir = File.expand_path File.join(File.dirname(__FILE__))
$LOAD_PATH.unshift spec_dir
$LOAD_PATH.uniq!

require "spec_helper"

shared_examples "token store" do
  before :each do
    store.store "default", "test"
  end

  it "should return a stored value" do
    expect(store.load("default")).to eq "test"
  end

  it "should return nil for missing tokens" do
    expect(store.load("notavalidkey")).to be_nil
  end

  it "should return nil for deleted tokens" do
    store.delete "default"
    expect(store.load("default")).to be_nil
  end

  it "should save overwrite values on store" do
    store.store "default", "test2"
    expect(store.load("default")).to eq "test2"
  end
end
