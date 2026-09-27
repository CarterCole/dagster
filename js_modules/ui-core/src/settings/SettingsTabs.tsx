import {Tabs} from '@dagster-io/ui-components';
import {useContext, useMemo} from 'react';
import {useLocation} from 'react-router-dom';

import {AppContext} from '../app/AppContext';
import {TabLink} from '../ui/TabLink';

const items = [
  {
    key: 'code-locations',
    label: 'Code locations',
    path: '/deployment/locations',
  },
  {
    key: 'daemons',
    label: 'Daemons',
    path: '/deployment/daemons',
  },
  {
    key: 'concurrency',
    label: 'Concurrency',
    path: '/deployment/concurrency',
  },
  {
    key: 'config',
    label: 'Configuration (read-only)',
    path: '/deployment/config',
  },
];

const accessControlItem = {
  key: 'access',
  label: 'Access control',
  path: '/deployment/access',
};

export const SettingsTabs = () => {
  const {pathname} = useLocation();
  const {accessControl} = useContext(AppContext);
  const visibleItems = useMemo(
    () => (accessControl?.enabled ? [...items, accessControlItem] : items),
    [accessControl],
  );
  const selectedTabId = useMemo(() => {
    const match = visibleItems.find((item) => pathname.startsWith(item.path));
    return match?.key;
  }, [pathname, visibleItems]);

  return (
    <Tabs selectedTabId={selectedTabId}>
      {visibleItems.map((item) => (
        <TabLink key={item.key} id={item.key} to={item.path} title={item.label} />
      ))}
    </Tabs>
  );
};
