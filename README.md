# netlify-site-clone

This is a tool to quickly create a clone of specific version of a netlify site.
Intended use is have Netlify build and deploy all commits (to all or just some branches) to your git repo, but that site would be used as kind of a [mother plant](https://en.wikipedia.org/wiki/Mother_plant). Actual user-accessible site (or sites: you do have dev, qa, and staging enviroments, don't you?) would be created using this tool as a part of some configuration management flow (not managed by Netlify). This approach allows rapidly (usually under half a minute, as it doesn't involve build process) deploying specific versions of your site to different environments. This way you can be sure that you deploy on production environment exactly the same version of the site that you have previously tested on qa/staging, and that you can rapidly deploy (and revert) any hot fixes.

There is also a rudimentary patching functionality that can be used to inject environment-specific settings.

This tool has been actively used in production in 2019-2020 and was feature complete at that time. However, some changes to Netlify's API might have rendered it broken: I haven't checked and there is no proper CI testing.
Should this tool be of any interest to anyone, I will try to write some proper documentation and maybe come up with some CI tests.
