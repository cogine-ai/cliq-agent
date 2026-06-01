import { Box, Text, useInput, type Key } from 'ink';
import { useEffect, useRef, useState } from 'react';

import {
  formatProviderStatusRow,
  type ProviderStatus,
  type ProviderStatusReport
} from '../../model/provider-status.js';

export type ProviderManagementProps = {
  report: ProviderStatusReport;
  onClose: () => void;
};

export function ProviderManagement({ report, onClose }: ProviderManagementProps) {
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [detail, setDetail] = useState<ProviderStatus | null>(null);
  const isActiveRef = useRef(false);
  const [isActive, setIsActive] = useState(false);

  useEffect(() => {
    isActiveRef.current = false;
    setIsActive(false);
    const handle = setImmediate(() => {
      isActiveRef.current = true;
      setIsActive(true);
    });
    return () => {
      clearImmediate(handle);
      isActiveRef.current = false;
    };
  }, [report]);

  useInput((input: string, key: Key) => {
    if (!isActiveRef.current) return;
    if (input === 'q' || input === 'Q' || key.escape) {
      onClose();
      return;
    }

    if (detail) {
      if (input === 'b' || input === 'B' || key.leftArrow || key.backspace || key.delete) {
        setDetail(null);
      }
      return;
    }

    if (key.downArrow || input === 'j' || input === 'J') {
      setSelectedIndex((current) => Math.min(current + 1, report.providers.length - 1));
      return;
    }
    if (key.upArrow || input === 'k' || input === 'K') {
      setSelectedIndex((current) => Math.max(current - 1, 0));
      return;
    }
    if (key.return) {
      const provider = report.providers[selectedIndex];
      if (provider) setDetail(provider);
    }
  });

  return (
    <Box flexDirection="column" borderStyle="round" borderColor="cyan" paddingX={1}>
      <Text color="cyan" bold>
        Provider management
      </Text>
      {detail ? <ProviderDetail provider={detail} report={report} /> : <ProviderList report={report} selectedIndex={selectedIndex} />}
      <Box marginTop={1}>
        {detail ? (
          <>
            <Text color="cyan">[b]ack </Text>
            <Text dimColor> Esc/q close</Text>
          </>
        ) : (
          <>
            <Text color="cyan">Enter details </Text>
            <Text dimColor> Up/Down select · Esc/q close</Text>
          </>
        )}
      </Box>
      {!isActive ? <Text dimColor>Waiting for fresh input...</Text> : null}
    </Box>
  );
}

function ProviderList({ report, selectedIndex }: { report: ProviderStatusReport; selectedIndex: number }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      {report.providers.map((provider, index) => (
        <Text key={provider.provider} color={index === selectedIndex ? 'cyan' : undefined}>
          {`${index === selectedIndex ? '> ' : '  '}${formatProviderStatusRow(provider)}`}
        </Text>
      ))}
    </Box>
  );
}

function ProviderDetail({ provider, report }: { provider: ProviderStatus; report: ProviderStatusReport }) {
  return (
    <Box flexDirection="column" marginTop={1}>
      <Text bold>{provider.displayName}</Text>
      <Field label="state" value={provider.state} />
      {provider.sources.length > 0 ? <Field label="sources" value={provider.sources.join(', ')} /> : null}
      {provider.model ? <Field label="model" value={provider.model} /> : null}
      {provider.baseUrl ? <Field label="base URL" value={provider.baseUrl} /> : null}
      {provider.modelCount !== undefined ? <Field label="local models" value={String(provider.modelCount)} /> : null}
      {provider.issues.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text color="yellow">Requirements</Text>
          {provider.issues.map((issue) => (
            <Text key={`${provider.provider}:${issue.code}`}>{`- ${issue.requirement}: ${issue.message}`}</Text>
          ))}
        </Box>
      ) : null}
      {provider.setup.length > 0 ? (
        <Box flexDirection="column" marginTop={1}>
          <Text color="cyan">Setup</Text>
          {provider.setup.map((line) => (
            <Text key={`${provider.provider}:${line}`}>{`- ${line}`}</Text>
          ))}
        </Box>
      ) : null}
      <Box marginTop={1}>
        <Text dimColor>{report.credentialPersistence.message}</Text>
      </Box>
    </Box>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <Box>
      <Text dimColor>{`  ${label}: `}</Text>
      <Text>{value}</Text>
    </Box>
  );
}
