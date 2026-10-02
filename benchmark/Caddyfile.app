# The "application": a static answer, so what is measured is the proxy path, not an app.
{
	admin off
	auto_https off
}
:80 {
	header Content-Type "text/html; charset=utf-8"
	respond "<!doctype html><title>ok</title><p>hello from the app</p>" 200
}
