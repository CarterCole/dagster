import {
  Alert,
  BaseTag,
  Box,
  Button,
  Colors,
  ExternalAnchorButton,
  Heading,
  Icon,
  Menu,
  MenuItem,
  Select,
  Spinner,
  Table,
  TagSelector,
  Text,
  TextInput,
} from '@dagster-io/ui-components';
import {useCallback, useContext, useEffect, useMemo, useState} from 'react';

import {AppContext} from '../app/AppContext';
import {useTrackPageView} from '../app/analytics';
import {useDocumentTitle} from '../hooks/useDocumentTitle';

type Role = 'none' | 'viewer' | 'launcher' | 'editor' | 'admin';
type PrincipalType = 'user' | 'group';

interface AccessRule {
  principalType: PrincipalType;
  principal: string;
  role: Role;
  locations: string[];
}

interface AccessPolicy {
  defaultRole: Role;
  rules: AccessRule[];
}

interface ViewerAccess {
  user: {email: string; name: string | null; groups: string[]};
  isAdmin: boolean;
  globalRole: Role;
  locationRoles: Record<string, Role>;
}

interface PolicyResponse {
  policy: AccessPolicy;
  bootstrapAdmins: {users: string[]; groups: string[]};
  locationNames: string[];
}

// Rules get a client-side key so React can track rows while principals are being edited.
type EditableRule = AccessRule & {key: number};

const ALL_LOCATIONS = '*';

const ROLES: {role: Role; label: string; description: string}[] = [
  {role: 'none', label: 'No access', description: 'Cannot see runs'},
  {role: 'viewer', label: 'Viewer', description: 'Can see runs and their logs'},
  {
    role: 'launcher',
    label: 'Launcher',
    description: 'Can also launch, re-execute and terminate runs and backfills',
  },
  {
    role: 'editor',
    label: 'Editor',
    description: 'Can also manage schedules, sensors, assets and partitions',
  },
  {role: 'admin', label: 'Admin', description: 'Everything, plus managing this page'},
];

const roleLabel = (role: Role) => ROLES.find((r) => r.role === role)?.label ?? role;

const locationLabel = (location: string) =>
  location === ALL_LOCATIONS ? 'All code locations' : location;

async function requestJSON<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, {
    credentials: 'same-origin',
    ...init,
    headers: {Accept: 'application/json', ...init?.headers},
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.error ?? `Request failed with status ${response.status}`);
  }
  return body as T;
}

let nextRuleKey = 0;
const toEditable = (rules: AccessRule[]): EditableRule[] =>
  rules.map((rule) => ({...rule, key: nextRuleKey++}));

const fromEditable = (rules: EditableRule[]): AccessRule[] =>
  rules.map(({principalType, principal, role, locations}) => ({
    principalType,
    principal: principal.trim(),
    role,
    locations,
  }));

export const AccessControlPageContent = () => {
  useTrackPageView();
  useDocumentTitle('Access control');

  const {rootServerURI} = useContext(AppContext);
  const [access, setAccess] = useState<ViewerAccess | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  useEffect(() => {
    requestJSON<ViewerAccess>(`${rootServerURI}/auth/me`)
      .then(setAccess)
      .catch((e: Error) => setLoadError(e.message));
  }, [rootServerURI]);

  if (loadError) {
    return (
      <Box padding={24}>
        <Alert intent="error" title="Could not load your access" description={loadError} />
      </Box>
    );
  }

  if (!access) {
    return (
      <Box padding={{vertical: 64}}>
        <Spinner purpose="section" />
      </Box>
    );
  }

  return (
    <Box flex={{direction: 'column'}} style={{overflowY: 'auto', flex: 1}}>
      <Box
        padding={{vertical: 16, horizontal: 24}}
        border="bottom"
        flex={{direction: 'row', alignItems: 'center', justifyContent: 'space-between'}}
      >
        <Box flex={{direction: 'column', gap: 4}}>
          <Heading size={14} weight={600}>
            Signed in as{' '}
            {access.user.name ? `${access.user.name} (${access.user.email})` : access.user.email}
          </Heading>
          <Text size={12} color="textLight">
            {access.user.groups.length
              ? `Okta groups: ${access.user.groups.join(', ')}`
              : 'No Okta groups were shared with Dagster'}
          </Text>
        </Box>
        <ExternalAnchorButton href={`${rootServerURI}/auth/logout`} icon={<Icon name="logout" />}>
          Sign out
        </ExternalAnchorButton>
      </Box>
      <YourAccess access={access} />
      {access.isAdmin ? (
        <PolicyEditor />
      ) : (
        <Box padding={{horizontal: 24, bottom: 24}}>
          <Text size={14} color="textLight">
            Only admins can change who has access. Ask a Dagster admin if you need more access.
          </Text>
        </Box>
      )}
    </Box>
  );
};

const YourAccess = ({access}: {access: ViewerAccess}) => {
  const locationRoles = Object.entries(access.locationRoles).sort(([a], [b]) => a.localeCompare(b));
  return (
    <Box padding={24} flex={{direction: 'column', gap: 8}}>
      <Heading size={16} weight={600}>
        Your access
      </Heading>
      <Text size={14}>
        {roleLabel(access.globalRole)} on all code locations
        {locationRoles.length ? ', plus:' : '.'}
      </Text>
      {locationRoles.length ? (
        <ul style={{margin: 0}}>
          {locationRoles.map(([location, role]) => (
            <li key={location}>
              <Text size={14}>
                {roleLabel(role)} on <strong>{location}</strong>
              </Text>
            </li>
          ))}
        </ul>
      ) : null}
    </Box>
  );
};

const PolicyEditor = () => {
  const {rootServerURI} = useContext(AppContext);
  const policyUrl = `${rootServerURI}/auth/api/policy`;

  const [saved, setSaved] = useState<PolicyResponse | null>(null);
  const [defaultRole, setDefaultRole] = useState<Role>('none');
  const [rules, setRules] = useState<EditableRule[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [justSaved, setJustSaved] = useState(false);

  const applyResponse = useCallback((response: PolicyResponse) => {
    setSaved(response);
    setDefaultRole(response.policy.defaultRole);
    setRules(toEditable(response.policy.rules));
  }, []);

  useEffect(() => {
    requestJSON<PolicyResponse>(policyUrl)
      .then(applyResponse)
      .catch((e: Error) => setError(e.message));
  }, [policyUrl, applyResponse]);

  const draft: AccessPolicy = useMemo(
    () => ({defaultRole, rules: fromEditable(rules)}),
    [defaultRole, rules],
  );
  const dirty = !!saved && JSON.stringify(draft) !== JSON.stringify(saved.policy);

  const problems = useMemo(() => {
    const found: string[] = [];
    draft.rules.forEach((rule, index) => {
      if (!rule.principal) {
        found.push(
          `Rule ${index + 1} needs a ${rule.principalType === 'user' ? 'email' : 'group'}.`,
        );
      }
      if (!rule.locations.length) {
        found.push(`Rule ${index + 1} needs at least one code location.`);
      }
    });
    return found;
  }, [draft]);

  const updateRule = (key: number, changes: Partial<AccessRule>) => {
    setJustSaved(false);
    setRules((current) => current.map((rule) => (rule.key === key ? {...rule, ...changes} : rule)));
  };

  const save = async () => {
    setSaving(true);
    setError(null);
    try {
      applyResponse(
        await requestJSON<PolicyResponse>(policyUrl, {
          method: 'PUT',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(draft),
        }),
      );
      setJustSaved(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSaving(false);
    }
  };

  if (!saved) {
    return error ? (
      <Box padding={{horizontal: 24, bottom: 24}}>
        <Alert intent="error" title="Could not load the access policy" description={error} />
      </Box>
    ) : (
      <Box padding={{vertical: 32}}>
        <Spinner purpose="section" />
      </Box>
    );
  }

  const allLocations = [ALL_LOCATIONS, ...saved.locationNames];
  const {users: adminUsers, groups: adminGroups} = saved.bootstrapAdmins;

  return (
    <Box padding={{horizontal: 24, bottom: 24}} flex={{direction: 'column', gap: 16}}>
      <Box border="top" padding={{top: 24}} flex={{direction: 'column', gap: 4}}>
        <Heading size={16} weight={600}>
          Access policy
        </Heading>
        <Text size={14} color="textLight">
          Each person gets the highest role any matching rule grants them. Users are matched by
          email, groups by their exact Okta group name. Changes apply to all webservers within a few
          seconds.
        </Text>
      </Box>

      {adminUsers.length || adminGroups.length ? (
        <Alert
          intent="info"
          title="Always admins"
          description={`Set in dagster.yaml, so they can't be locked out: ${[
            ...adminUsers,
            ...adminGroups.map((group) => `group ${group}`),
          ].join(', ')}.`}
        />
      ) : null}

      <Box flex={{direction: 'row', alignItems: 'center', gap: 12}}>
        <Text size={14}>Everyone who signs in gets</Text>
        <RoleSelect
          value={defaultRole}
          allowAdmin={false}
          onChange={(role) => {
            setJustSaved(false);
            setDefaultRole(role);
          }}
        />
        <Text size={14}>on all code locations.</Text>
      </Box>

      <Table>
        <thead>
          <tr>
            <th style={{width: 120}}>Type</th>
            <th>User email or Okta group</th>
            <th style={{width: 160}}>Role</th>
            <th>Code locations</th>
            <th style={{width: 48}} />
          </tr>
        </thead>
        <tbody>
          {rules.length === 0 ? (
            <tr>
              <td colSpan={5}>
                <Text size={14} color="textLight">
                  No rules yet. Add one to give a user or group access.
                </Text>
              </td>
            </tr>
          ) : null}
          {rules.map((rule) => (
            <tr key={rule.key}>
              <td>
                <PrincipalTypeSelect
                  value={rule.principalType}
                  onChange={(principalType) => updateRule(rule.key, {principalType})}
                />
              </td>
              <td>
                <TextInput
                  fill
                  value={rule.principal}
                  placeholder={
                    rule.principalType === 'user' ? 'person@example.com' : 'Okta group name'
                  }
                  onChange={(e) => updateRule(rule.key, {principal: e.target.value})}
                />
              </td>
              <td>
                <RoleSelect
                  value={rule.role}
                  allowAdmin
                  onChange={(role) => updateRule(rule.key, {role})}
                />
              </td>
              <td>
                <TagSelector
                  allTags={allLocations}
                  selectedTags={rule.locations}
                  setSelectedTags={(locations) => updateRule(rule.key, {locations})}
                  placeholder="Select code locations"
                  renderTag={(location, {remove}) => (
                    <BaseTag
                      key={location}
                      fillColor={Colors.backgroundGray()}
                      textColor={Colors.textDefault()}
                      label={
                        <Box flex={{direction: 'row', gap: 4, alignItems: 'center'}}>
                          {locationLabel(location)}
                          <Box style={{cursor: 'pointer'}} onClick={remove}>
                            <Icon name="close" />
                          </Box>
                        </Box>
                      }
                    />
                  )}
                  renderDropdownItem={(location, {toggle, selected}) => (
                    <MenuItem
                      key={location}
                      text={locationLabel(location)}
                      icon={selected ? 'checkbox_checked' : 'checkbox_empty'}
                      onClick={toggle}
                    />
                  )}
                  usePortal
                />
              </td>
              <td>
                <Button
                  icon={<Icon name="delete" />}
                  aria-label="Remove rule"
                  onClick={() => {
                    setJustSaved(false);
                    setRules((current) => current.filter((r) => r.key !== rule.key));
                  }}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </Table>

      <Box flex={{direction: 'row', alignItems: 'center', gap: 8}}>
        <Button
          icon={<Icon name="add" />}
          onClick={() => {
            setJustSaved(false);
            setRules((current) => [
              ...current,
              ...toEditable([
                {principalType: 'group', principal: '', role: 'viewer', locations: [ALL_LOCATIONS]},
              ]),
            ]);
          }}
        >
          Add rule
        </Button>
        <div style={{flex: 1}} />
        {justSaved && !dirty ? (
          <Text size={14} color="textLight">
            Saved
          </Text>
        ) : null}
        <Button disabled={!dirty || saving} onClick={() => applyResponse(saved)}>
          Discard changes
        </Button>
        <Button
          intent="primary"
          disabled={!dirty || saving || problems.length > 0}
          loading={saving}
          onClick={save}
        >
          Save changes
        </Button>
      </Box>

      {problems.length ? (
        <Alert intent="warning" title="Fix these before saving" description={problems.join(' ')} />
      ) : null}
      {error ? <Alert intent="error" title="Could not save" description={error} /> : null}

      <Box flex={{direction: 'column', gap: 4}}>
        <Heading size={14} weight={600}>
          Roles
        </Heading>
        {ROLES.map(({role, label, description}) => (
          <Text size={14} key={role}>
            <strong>{label}</strong>: {description}
            {role === 'admin'
              ? ' (on all code locations; on a single location it acts as Editor)'
              : ''}
          </Text>
        ))}
      </Box>
    </Box>
  );
};

const RoleSelect = ({
  value,
  allowAdmin,
  onChange,
}: {
  value: Role;
  allowAdmin: boolean;
  onChange: (role: Role) => void;
}) => {
  const items = ROLES.filter(({role}) => allowAdmin || role !== 'admin');
  return (
    <Select<(typeof items)[0]>
      filterable={false}
      activeItem={items.find((item) => item.role === value)}
      items={items}
      itemRenderer={(item, props) => (
        <MenuItem
          key={item.role}
          active={props.modifiers.active}
          onClick={props.handleClick}
          text={item.label}
          style={{width: 240}}
        />
      )}
      itemListRenderer={({renderItem, filteredItems}) => (
        <Menu>{filteredItems.map(renderItem).filter(Boolean)}</Menu>
      )}
      onItemSelect={(item) => onChange(item.role)}
    >
      <Button
        rightIcon={<Icon name="arrow_drop_down" />}
        style={{minWidth: 140, display: 'flex', justifyContent: 'space-between'}}
      >
        {roleLabel(value)}
      </Button>
    </Select>
  );
};

const PRINCIPAL_TYPES: {type: PrincipalType; label: string}[] = [
  {type: 'group', label: 'Group'},
  {type: 'user', label: 'User'},
];

const PrincipalTypeSelect = ({
  value,
  onChange,
}: {
  value: PrincipalType;
  onChange: (type: PrincipalType) => void;
}) => (
  <Select<(typeof PRINCIPAL_TYPES)[0]>
    filterable={false}
    activeItem={PRINCIPAL_TYPES.find((item) => item.type === value)}
    items={PRINCIPAL_TYPES}
    itemRenderer={(item, props) => (
      <MenuItem
        key={item.type}
        active={props.modifiers.active}
        onClick={props.handleClick}
        text={item.label}
      />
    )}
    itemListRenderer={({renderItem, filteredItems}) => (
      <Menu>{filteredItems.map(renderItem).filter(Boolean)}</Menu>
    )}
    onItemSelect={(item) => onChange(item.type)}
  >
    <Button
      rightIcon={<Icon name="arrow_drop_down" />}
      style={{minWidth: 100, display: 'flex', justifyContent: 'space-between'}}
    >
      {PRINCIPAL_TYPES.find((item) => item.type === value)?.label}
    </Button>
  </Select>
);
