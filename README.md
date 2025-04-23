# GS1DigitalLicenses

This github repo contains the document development for the simplified GS1 VC Data Model.

View the document [here](https://woodycreek.github.io/GS1DigitalLicenses/).

# Viewing in web server

Its best to view this in a webserver since content is dynamic. I use

```
python -m http.server 8000
```

# Generation

I used this to build this document

## Install respec for npm

```
npm install -g respec
```

## Generate output html

```
respec index.html -o output.html
```

## Render

```
open output.html
```
