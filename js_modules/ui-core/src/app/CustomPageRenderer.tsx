import {Box, Spinner} from '@dagster-io/ui-components';
import * as React from 'react';

import {Markdown} from '../ui/Markdown';

export const CustomPageRenderer = ({
  uiPath,
  filePath,
  match,
}: {
  uiPath: string;
  filePath: string;
  match: any;
}) => {
  const [content, setContent] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    fetch(`/api/custom_page?uiPath=${encodeURIComponent(uiPath)}`)
      .then((res) => {
        if (!res.ok) {
          throw new Error('Failed to load page content');
        }
        return res.text();
      })
      .then(setContent)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [uiPath]);

  if (loading) {
    return (
      <Box padding={24} flex={{justifyContent: 'center'}}>
        <Spinner purpose="section" />
      </Box>
    );
  }

  if (error) {
    return <Box padding={24}>Error: {error}</Box>;
  }

  if (!content) {
    return null;
  }

  if (filePath.endsWith('.md')) {
    return (
      <Box padding={24}>
        <Markdown>{content}</Markdown>
      </Box>
    );
  }

  if (filePath.endsWith('.jsx')) {
    return <JSXComponentRenderer content={content} routeProps={match.params} />;
  }

  return (
    <Box padding={24}>
      <pre style={{whiteSpace: 'pre-wrap'}}>{content}</pre>
    </Box>
  );
};

const JSXComponentRenderer = ({content, routeProps}: {content: string; routeProps: any}) => {
  const [Comp, setComp] = React.useState<any>(null);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    const loadAndCompile = async () => {
      try {
        if (!(window as any).Babel) {
          const script = document.createElement('script');
          script.src = 'https://unpkg.com/@babel/standalone/babel.min.js';
          document.head.appendChild(script);
          await new Promise((resolve) => (script.onload = resolve));
        }

        const transformed = (window as any).Babel.transform(content, {
          presets: ['react'],
        }).code;

        // Wrap the transformed code to capture the export
        const result = new Function('React', 'routeProps', `
          const exports = {};
          ${transformed}
          return exports.default || Object.values(exports)[0];
        `)(React, routeProps);

        setComp(() => result);
      } catch (e: any) {
        setError(e.message);
      }
    };
    loadAndCompile();
  }, [content, routeProps]);

  if (error) {
    return <Box padding={24}>Compilation Error: {error}</Box>;
  }

  if (!Comp) {
    return (
      <Box padding={24} flex={{justifyContent: 'center'}}>
        <Spinner purpose="section" />
      </Box>
    );
  }

  return <Comp {...routeProps} />;
};
