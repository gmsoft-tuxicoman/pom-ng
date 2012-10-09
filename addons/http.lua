
require "pom"

http_out = output.new("http", {
	{ "prefix", "string", "/tmp/", "Prefix where to save the files" },
	{ "log_file", "string", "http.xml", "Log filename" },
	{ "dump_img", "bool", "yes", "Enable dumping images" },
	{ "img_min_surface", "uint32", 300 * 300, "Minimum image surface (height * width)" },
	{ "dump_vid", "bool", "yes", "Enable dumping videos" }
})

function http_out:pload_open(priv, pload)

	local event = pload.event

	-- Make sure the payload is coming from the right event
	if event.name ~= "http_request" then return end

	-- Check if we need to process this payload
	local process = false
	local pload_type = pload.type
	if pload_type == nil then return end

	local class = pload_type['class']

	-- Check for images and the minimum surface
	if class == "image" and self:param_get("dump_img") then
		local surface = pload.data["height"] * pload.data["width"]
		if surface >= self:param_get("img_min_surface") then process = true end
	end

	-- Check for video
	if class == "video" and self:param_get("dump_vid") then process = true end

	-- Process it (or not)
	if process then
		local filename = self.prefix .. event.data["server_name"] ..  event.data["url"]
		pom.log(POMLOG_DEBUG, "Saving file into " .. filename)
		self.files:pload_process(pload, { filename = filename } )
		self.log:event_process(event)
	end

end

function http_out:open()

	-- Open the file plugin that saves payloads to the disk
	self.files = plugin.new("file")
	self.files:open()

	-- Open the log_xml plugin to log requests on the disk
	self.log = plugin.new("log_xml")
	self.log:param_set("filename", self:param_get("log_file"))
	self.log:open()

	-- Listen to payloads
	self:pload_listen_start(self.pload_open, nil, nil)

	-- We need to listen to the http_request event so it will generate payloads
	self:event_listen_start("http_request")

	-- Copy the prefix parameter for faster execution
	self.prefix = self:param_get("prefix")

end

function http_out:close()

	-- Stop listening to the event http_request
	self:event_listen_stop("http_request")

	-- Stop listening to payloads
	self:pload_listen_stop()

	-- Close the plugins
	self.files:close()
	self.log:close()


end

function http_register()
	
	-- Register our new output
	output.register(http_out)	
end


