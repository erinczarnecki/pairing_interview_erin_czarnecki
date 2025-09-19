# Run: ruby starters/ruby.rb

require "csv"

CVSS_V1_SCORES = {
  "AV" => { "N" => 1.0, "L" => 0.65, "P" => 0.4 },
  "AC" => { "L" => 0.8, "H" => 0.6 },
  "I" => { "C" => 1.0, "H" => 0.75, "L" => 0.5 }
}

CVSS_V2_SCORES = {
  "AV" => { "N" => 1.0, "A" => 0.646, "L" => 0.395, "P" => 0.2 },
  "AC" => { "L" => 0.71, "M" => 0.61, "H" => 0.35 },
  "Au" => { "N" => 0.704, "S" => 0.56, "M" => 0.45 },
  "I" => { "C" => 1.0, "H" => 0.75, "L" => 0.5 }
}

CSV.read("cves.csv", headers: true).each do |row|
  puts row.inspect
end
