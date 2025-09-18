# Data Lineage Diagram for Digital Innovation & Products

## Mermaid Diagram

```mermaid
graph TD
    %% External Data Sources (Based on actual YAML documentation)
    ExtSources[External Sources<br/>Events via Webhooks/ETL]
    
    %% S3 Raw Data Layers (Bronze) - Documented in YAML
    S3_GenEvents[S3: General Events<br/>s3://eno-dm-bronze-*/enode/landing/<br/>generalEvents-*.json]
    S3_VehEvents[S3: Vehicle Events<br/>s3://eno-dm-bronze-*/enode/landing/<br/>vehicleEvents-*.json]
    S3_InvEvents[S3: Inverter Events<br/>s3://eno-dm-bronze-*/enode/landing/<br/>inverterEvents-*.json]
    
    %% PostgreSQL ODS Tables (Silver) - Documented in YAML
    PG_Users[PostgreSQL ODS<br/>asset.users]
    PG_Vehicles[PostgreSQL ODS<br/>asset.vehicles]
    PG_Inverters[PostgreSQL ODS<br/>asset.inverters]
    PG_VehCharges[PostgreSQL ODS<br/>asset.vehicles_charges]
    PG_SmartCharging[PostgreSQL ODS<br/>asset.smart_charging_status]
    PG_InvProduction[PostgreSQL ODS<br/>asset.inverters_production]
    PG_InvLoadProfile[PostgreSQL ODS<br/>asset.inverters_load_profile]
    
    %% Data Flow from External Sources to S3 (documented servers)
    ExtSources --> S3_GenEvents
    ExtSources --> S3_VehEvents
    ExtSources --> S3_InvEvents
    
    %% Data Flow from S3 to PostgreSQL ODS
    S3_GenEvents --> PG_Users
    S3_VehEvents --> PG_Vehicles
    S3_VehEvents --> PG_VehCharges
    S3_VehEvents --> PG_SmartCharging
    S3_InvEvents --> PG_Inverters
    S3_InvEvents --> PG_InvProduction
    S3_InvEvents --> PG_InvLoadProfile
    
    %% Relationships between PostgreSQL tables
    PG_Users -->|owner_id| PG_Vehicles
    PG_Users -->|owner_id| PG_Inverters
    PG_Vehicles -->|vehicle_id| PG_VehCharges
    PG_Vehicles -->|vehicle_id| PG_SmartCharging
    PG_Inverters -->|inverter_id| PG_InvProduction
    PG_Inverters -->|inverter_id| PG_InvLoadProfile
      %% Styling
    classDef extNode fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef s3Node fill:#fff8e1,stroke:#f57c00,stroke-width:2px
    classDef pgNode fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    
    class ExtSources extNode
    class S3_GenEvents,S3_VehEvents,S3_InvEvents s3Node
    class PG_Users,PG_Vehicles,PG_Inverters,PG_VehCharges,PG_SmartCharging,PG_InvProduction,PG_InvLoadProfile pgNode
```

## Data Contract Mapping

### Bronze Layer (S3 Raw Data)

| Data Product | Location | Schema Objects | Tags |
|--------------|----------|----------------|------|
| **EnodeCredentialEventBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/generalEvents-*.json` | CredentialsInvalidatedEvent | Assets, Inverter |
| **EnodeVendorUpdateBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/generalEvents-*.json` | VendorActionUpdatedEvent | Assets, Inverter |
| **EnodeVehicleEventBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/vehicleEvents-*.json` | VehicleUpdatedEvent | Assets, Vehicle |
| **EnodeSmartChargingEventBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/vehicleEvents-*.json` | SmartChargingStatusUpdatedEvent | Assets, Vehicle |
| **EnodeInverterEventBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/inverterEvents-*.json` | InverterDiscoveredEvent | Assets, Inverter |
| **EnodeInverterStatisticsUpdateBronze** | `s3://eno-dm-bronze-*/enode/landing/*/*/inverterEvents-*.json` | InverterStatisticsUpdatedEvent | Assets, Inverter |

### Silver Layer (PostgreSQL ODS)

| Data Product | Database Schema | Table Name | Primary Key | Foreign Keys | Tags |
|--------------|-----------------|------------|-------------|--------------|------|
| **EnodeUser** | asset.users | users | owner_id | - | User, ElectricVeichle, Inverter |
| **EnodeAsset** | asset.vehicles | vehicles | id | owner_id → users.owner_id | Asset, ElectricVeichle, Inverter |
| **EnodeAsset** | asset.inverters | inverters | id | owner_id → users.owner_id | Asset, ElectricVeichle, Inverter |
| **EnodeEVEvents** | asset.vehicles_charges | vehicles_charges | id | vehicle_id → vehicles.id | ElectricVeichle, Event |
| **EnodeEVEvents** | asset.smart_charging_status | smart_charging_status | id | vehicle_id → vehicles.id | ElectricVeichle, Event, SmartCharging |
| **EnodeInverterEvent** | asset.inverters_production | inverters_production | id | inverter_id → inverters.id | Inverter, Event, Photovoltaic |
| **EnodeInverterEvent** | asset.inverters_load_profile | inverters_load_profile | id | inverter_id → inverters.id | Inverter, Event, Photovoltaic |

### Key Relationships

1. **Users** are the foundation, with `owner_id` as the primary identifier
2. **Vehicles** and **Inverters** are assets owned by users (foreign key: `owner_id`)
3. **Vehicle Events** (charges, smart charging) reference vehicles (foreign key: `vehicle_id`)
4. **Inverter Events** (production, load profile) reference inverters (foreign key: `inverter_id`)

### Data Flow

1. **Bronze Layer**: Raw JSON events stored in S3 buckets organized by event type (documented in YAML server configurations)
2. **Silver Layer**: Processed and structured data in PostgreSQL ODS with normalized relationships
3. **Event Processing**: S3 events are transformed and loaded into PostgreSQL tables maintaining referential integrity

**Note**: The actual source of data flowing into S3 is not explicitly documented in the YAML files. The data contracts only specify S3 as the server location. References to Enode API and webhooks are found only in archived contracts.
