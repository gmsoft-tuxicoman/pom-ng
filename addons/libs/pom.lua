
function pom.data_dump(data)
	local data_iter = pom.data_iterator(data)
	while true do
		local k, v
		k,v = data_iter()
		if not k then break end
		local t = type(v)

		-- display the tables
		if t == "userdata" then
			
			-- iterate through each values in the table
			local data_item_iter = pom.data_item_iterator(v);
			while true do
				local ik, iv
				ik, iv = data_item_iter()
				if not ik then break end
				io.write(k .. "[".. ik .. "]" .. " = " .. iv .. "\n")
			end

		-- display values
		elseif t ~= "nil" then
			io.write(k .. ": " .. v  .. "\n");

		-- display nil values
		else
			io.write(k .. ": <empty>\n");
		end
	end
end

