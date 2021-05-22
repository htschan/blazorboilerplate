@echo off
docker build -t htschan/blazor -f .\Server\BlazorBoilerplate.Server\Dockerfile .
docker push htschan/blazor
