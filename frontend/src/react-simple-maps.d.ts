declare module 'react-simple-maps' {
  import type { ComponentType, CSSProperties, ReactNode, SVGProps } from 'react';

  export interface GeographyFeature {
    rsmKey: string;
    [key: string]: unknown;
  }

  export interface GeographiesRenderProps {
    geographies: GeographyFeature[];
  }

  export const ComposableMap: ComponentType<
    SVGProps<SVGSVGElement> & {
      projection?: string;
      projectionConfig?: Record<string, unknown>;
    }
  >;

  export const Geographies: ComponentType<{
    geography: string;
    children: (props: GeographiesRenderProps) => ReactNode;
  }>;

  export const Geography: ComponentType<
    {
      geography: GeographyFeature;
      fill?: string;
      stroke?: string;
      strokeWidth?: number;
      className?: string;
      style?: {
        default?: CSSProperties;
        hover?: CSSProperties;
        pressed?: CSSProperties;
      };
    }
  >;

  export const Line: ComponentType<
    {
      from: [number, number];
      to: [number, number];
      stroke?: string;
      strokeWidth?: number;
      strokeLinecap?: string;
      className?: string;
      style?: CSSProperties;
    }
  >;

  export const Marker: ComponentType<
    {
      coordinates: [number, number];
      className?: string;
      children?: ReactNode;
    }
  >;
}
