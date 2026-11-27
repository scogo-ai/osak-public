if type != "array" then error("invalid Worker deployments response")
elif length == 0 then ""
else
  max_by(.created_on).versions | map(select(.percentage != 0)) |
  if length == 1 and .[0].percentage == 100 then
    .[0].version_id | select(type == "string" and length > 0)
  else error("current Worker traffic is split or invalid; cannot restore one version")
  end
end
