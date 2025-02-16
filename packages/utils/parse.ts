import {
  InfoIcon,
  LightBulbIcon,
  MessageSquareWarningIcon,
  OctogonAlertIcon,
  TriangleAlertIcon,
} from '@modrinth/assets/raw'
import MarkdownIt from 'markdown-it'
import MarkdownItGitHubAlerts from 'markdown-it-github-alerts'
import { escapeAttrValue, FilterXSS, safeAttrValue, whiteList, IFilterXSSOptions } from 'xss'

const defaultFilter: IFilterXSSOptions = {
  whiteList: {
    ...whiteList,
    summary: [],
    h1: ['id'],
    h2: ['id'],
    h3: ['id'],
    h4: ['id'],
    h5: ['id'],
    h6: ['id'],
    kbd: ['id'],
    input: ['checked', 'disabled', 'type'],
    iframe: ['width', 'height', 'allowfullscreen', 'frameborder', 'start', 'end'],
    img: [...(whiteList.img || []), 'usemap', 'style', 'align'],
    map: ['name'],
    area: [...(whiteList.a || []), 'coords'],
    a: [...(whiteList.a || []), 'rel'],
    td: [...(whiteList.td || []), 'style'],
    th: [...(whiteList.th || []), 'style'],
    picture: [],
    source: ['media', 'sizes', 'src', 'srcset', 'type'],
    p: [...(whiteList.p || []), 'align'],
    div: [...(whiteList.p || []), 'align'],
  },
  css: {
    whiteList: {
      'image-rendering': /^pixelated$/,
      'text-align': /^center|left|right$/,
      float: /^left|right$/,
    },
  },
  onIgnoreTagAttr: (tag, name, value) => {
    // Allow iframes from acceptable sources
    if (tag === 'iframe' && name === 'src') {
      const allowedSources = [
        {
          url: /^https?:\/\/(www\.)?youtube(-nocookie)?\.com\/embed\/[a-zA-Z0-9_-]{11}/,
          allowedParameters: [/start=\d+/, /end=\d+/],
        },
        {
          url: /^https?:\/\/(www\.)?discord\.com\/widget/,
          allowedParameters: [/id=\d{18,19}/],
        },
      ]

      const url = new URL(value)

      for (const source of allowedSources) {
        if (!source.url.test(url.href)) {
          continue
        }

        const newSearchParams = new URLSearchParams()
        url.searchParams.forEach((value, key) => {
          if (!source.allowedParameters.some((param) => param.test(`${key}=${value}`))) {
            newSearchParams.delete(key)
          }
        })

        url.search = newSearchParams.toString()
        return `${name}="${escapeAttrValue(url.toString())}"`
      }
    }

    // For Highlight.JS
    if (name === 'class' && ['pre', 'code', 'span'].includes(tag)) {
      const allowedClasses: string[] = []
      for (const className of value.split(/\s/g)) {
        if (className.startsWith('hljs-') || className.startsWith('language-')) {
          allowedClasses.push(className)
        }
      }
      return `${name}="${escapeAttrValue(allowedClasses.join(' '))}"`
    }
  },
  safeAttrValue(tag, name, value, cssFilter) {
    if (
      (tag === 'img' || tag === 'video' || tag === 'audio' || tag === 'source') &&
      (name === 'src' || name === 'srcset') &&
      !value.startsWith('data:')
    ) {
      try {
        const url = new URL(value)

        if (url.hostname.includes('wsrv.nl')) {
          url.searchParams.delete('errorredirect')
        }

        const allowedHostnames = [
          'imgur.com',
          'i.imgur.com',
          'cdn-raw.modrinth.com',
          'cdn.modrinth.com',
          'staging-cdn-raw.modrinth.com',
          'staging-cdn.modrinth.com',
          'github.com',
          'raw.githubusercontent.com',
          'img.shields.io',
          'i.postimg.cc',
          'wsrv.nl',
          'cf.way2muchnoise.eu',
          'bstats.org',
        ]

        if (!allowedHostnames.includes(url.hostname)) {
          return safeAttrValue(
            tag,
            name,
            `https://wsrv.nl/?url=${encodeURIComponent(
              url.toString().replaceAll('&amp;', '&'),
            )}&n=-1`,
            cssFilter,
          )
        }
        return safeAttrValue(tag, name, url.toString(), cssFilter)
      } catch {
        /* empty */
      }
    }

    return safeAttrValue(tag, name, value, cssFilter)
  },
}

const alertFilter: IFilterXSSOptions = {
  ...defaultFilter,
  whiteList: {
    ...defaultFilter.whiteList,
    svg: [
      'aria-hidden',
      'width',
      'height',
      'viewBox',
      'fill',
      'stroke',
      'stroke-width',
      'stroke-linecap',
      'stroke-linejoin',
    ],
    path: ['d'],
    circle: ['cx', 'cy', 'r'],
    line: ['x1', 'x2', 'y1', 'y2'],
  },
  onIgnoreTagAttr: (tag, name, value, isWhiteAttr) => {
    const defaultResult = defaultFilter.onIgnoreTagAttr!(tag, name, value, isWhiteAttr);
    if (typeof defaultResult === "string") {
      return defaultResult
    }

    // For markdown callouts
    if (name === 'class' && ['div', 'p'].includes(tag)) {
      const classWhitelist = [
        'markdown-alert',
        'markdown-alert-note',
        'markdown-alert-tip',
        'markdown-alert-warning',
        'markdown-alert-important',
        'markdown-alert-caution',
        'markdown-alert-title',
      ]

      const allowed: string[] = []
      for (const className of value.split(/\s/g)) {
        if (classWhitelist.includes(className)) {
          allowed.push(className)
        }
      }

      return `${name}="${escapeAttrValue(allowed.join(' '))}"`
    }
  }
}

// More strictly sanitize raw HTML on the Markdown
const strictXss = new FilterXSS(defaultFilter)
/*
Use a filter that allows SVG and some classes to allow the alert icons and styles to render
The more strict filter is used on html blocks and inline in the main markdown
*/
export const configuredXss = new FilterXSS(alertFilter)

export const md = (options = {}) => {
  const md = new MarkdownIt('default', {
    html: true,
    linkify: true,
    breaks: false,
    ...options,
  })

  // More strictly sanitize raw HTML on the Markdown
  const defaultHtmlBlockRenderer =
    md.renderer.rules.html_block ||
    function (tokens, idx) {
      return tokens[idx].content
    }

  md.renderer.rules.html_block = function (tokens, idx, options, env, slf) {
    const original = defaultHtmlBlockRenderer(tokens, idx, options, env, slf)
    return strictXss.process(original)
  }

  const defaultHtmlInlineRenderer =
    md.renderer.rules.html_inline ||
    function (tokens, idx) {
      return tokens[idx].content
    }

  md.renderer.rules.html_inline = function (tokens, idx, options, env, slf) {
    const original = defaultHtmlInlineRenderer(tokens, idx, options, env, slf)
    return strictXss.process(original)
  }

  md.use(MarkdownItGitHubAlerts, {
    icons: {
      note: InfoIcon,
      tip: LightBulbIcon,
      important: MessageSquareWarningIcon,
      warning: TriangleAlertIcon,
      caution: OctogonAlertIcon,
    },
  })

  const defaultLinkOpenRenderer =
    md.renderer.rules.link_open ||
    function (tokens, idx, options, _env, self) {
      return self.renderToken(tokens, idx, options)
    }

  md.renderer.rules.link_open = function (tokens, idx, options, env, self) {
    const token = tokens[idx]
    const index = token.attrIndex('href')

    if (token.attrs && index !== -1) {
      const href = token.attrs[index][1]

      try {
        const url = new URL(href)
        const allowedHostnames = ['modrinth.com']

        if (allowedHostnames.includes(url.hostname)) {
          return defaultLinkOpenRenderer(tokens, idx, options, env, self)
        }
      } catch {
        /* empty */
      }
    }

    tokens[idx].attrSet('rel', 'noopener nofollow ugc')

    return defaultLinkOpenRenderer(tokens, idx, options, env, self)
  }

  return md
}

export const renderString = (string: string) => configuredXss.process(md().render(string))
