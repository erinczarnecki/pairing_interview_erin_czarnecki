# Run: elixir starters/elixir.exs

_cvss_v1_scores = %{
  "AV" => %{"N" => 1.0, "L" => 0.65, "P" => 0.4},
  "AC" => %{"L" => 0.8, "H" => 0.6},
  "I" => %{"C" => 1.0, "H" => 0.75, "L" => 0.5}
}

_cvss_v2_scores = %{
  "AV" => %{"N" => 1.0, "A" => 0.646, "L" => 0.395, "P" => 0.2},
  "AC" => %{"L" => 0.71, "M" => 0.61, "H" => 0.35},
  "Au" => %{"N" => 0.704, "S" => 0.56, "M" => 0.45},
  "I" => %{"C" => 1.0, "H" => 0.75, "L" => 0.5}
}

File.stream!("cves.csv")
|> Stream.drop(1)
|> Stream.map(&String.trim/1)
|> Stream.map(fn line ->
  [cve_id, cvss_vector] = String.split(line, ",")
  %{cve_id: cve_id, cvss_vector: cvss_vector}
end)
|> Enum.each(&IO.inspect/1)