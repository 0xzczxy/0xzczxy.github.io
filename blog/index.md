---
layout: default
title: Blog
permalink: /blog/
---

# Blog

Technical writeups, project deep-dives, and research notes.

---

{% for post in site.posts %}
## [{{ post.title }}]({{ post.url }})
**{{ post.date | date: "%B %d, %Y" }}**

{{ post.excerpt }}

[Read more →]({{ post.url }})

---
{% endfor %}
